# main.py
import os
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox

# The new library for professional themes
from ttkthemes import ThemedTk

# Import our custom modules
from scanner import Scanner
from reporting import build_pdf_report

APP_NAME = "Automated Recon Tool"
REPORTS_DIR = os.path.join(os.getcwd(), "reports")

# --- Define a more professional look and feel ---
COLORS = {
    "background": "#2D2D2D",
    "foreground": "#CCCCCC",
    "header": "#3D3D3D",
    "entry_bg": "#3C3C3C",
    "accent": "#007ACC",
    "accent_fg": "#FFFFFF",
    "tree_odd": "#3C3C3C",
    "tree_even": "#323232"
}

FONTS = {
    "header": ("Segoe UI", 16, "bold"),
    "label": ("Segoe UI", 11),
    "entry": ("Consolas", 12),
    "button": ("Segoe UI", 10, "bold"),
    "tree_heading": ("Segoe UI", 10, "bold"),
    "tree_data": ("Consolas", 10),
    "status": ("Segoe UI", 9)
}
# ---

class ReconApp(ThemedTk):
    def __init__(self):
        super().__init__()

        # Use a modern theme from ttkthemes
        self.set_theme("equilux")

        self.title(APP_NAME)
        self.geometry("1200x800")
        self.minsize(900, 600)
        
        os.makedirs(REPORTS_DIR, exist_ok=True)
        self.last_scan_result = None
        self.last_scan_target = None

        self._configure_styles()
        self._create_widgets()

    def _configure_styles(self):
        style = ttk.Style(self)
        style.configure('.', 
            background=COLORS["background"], 
            foreground=COLORS["foreground"],
            fieldbackground=COLORS["entry_bg"],
            font=FONTS["label"])
            
        style.configure('TButton', font=FONTS["button"], padding=6)
        style.map('TButton',
            background=[('active', COLORS["accent"])],
            foreground=[('active', COLORS["accent_fg"])])
            
        style.configure('Treeview', 
            rowheight=25, 
            font=FONTS["tree_data"],
            background=COLORS["entry_bg"])
        style.configure('Treeview.Heading', font=FONTS["tree_heading"])
        style.map('Treeview', background=[('selected', COLORS["accent"])])
        
        style.configure('Header.TLabel', 
            background=COLORS["header"], 
            foreground=COLORS["foreground"], 
            font=FONTS["header"],
            padding=10)
            
        style.configure('Status.TFrame', background=COLORS["header"])

    def _create_widgets(self):
        header_frame = ttk.Frame(self, style='Header.TLabel')
        header_frame.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(header_frame, text=APP_NAME, style='Header.TLabel').pack()

        main_frame = ttk.Frame(self, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.grid_rowconfigure(1, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=0, column=0, sticky='ew', pady=(0, 15))
        control_frame.grid_columnconfigure(1, weight=1)
        
        ttk.Label(control_frame, text="Target Domain:").grid(row=0, column=0, padx=(0, 10), sticky='w')
        self.target_entry = ttk.Entry(control_frame, font=FONTS["entry"], width=50)
        self.target_entry.grid(row=0, column=1, sticky='ew')
        
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=0, column=2, padx=(10, 0))
        self.start_btn = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 5))
        self.export_btn = ttk.Button(button_frame, text="Export PDF", command=self.export_pdf, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT)

        result_frame = ttk.Frame(main_frame)
        result_frame.grid(row=1, column=0, sticky='nsew')
        result_frame.grid_rowconfigure(0, weight=1)
        result_frame.grid_columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(result_frame, columns=('Value'), show='tree headings')
        self.tree.heading('#0', text='Scan Module / Key')
        self.tree.heading('Value', text='Result / Value')
        self.tree.column('#0', width=350, stretch=tk.NO)
        self.tree.column('Value', width=600)

        self.tree.tag_configure('oddrow', background=COLORS["tree_odd"])
        self.tree.tag_configure('evenrow', background=COLORS["tree_even"])

        vsb = ttk.Scrollbar(result_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(result_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        status_frame = ttk.Frame(self, style='Status.TFrame', padding=5)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_label = ttk.Label(status_frame, text="Ready", anchor='w', font=FONTS["status"], background=COLORS["header"])
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.progress_bar = ttk.Progressbar(status_frame, orient='horizontal', mode='determinate', length=200)
        self.progress_bar.pack(side=tk.RIGHT)

    def start_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Input Required", "Please enter a target domain.")
            return

        self.clear_results()
        self.last_scan_target = target
        self.start_btn.config(state=tk.DISABLED)
        self.export_btn.config(state=tk.DISABLED)
        self.progress_bar['value'] = 0

        thread = threading.Thread(target=self._scan_worker, args=(target,), daemon=True)
        thread.start()

    def _scan_worker(self, target: str):
        # Updated from 7 to 9 to reflect the new scans (Geolocation, Robots/Sitemap)
        total_modules = 9 
        self.modules_done = 0

        def progress_callback(status_text: str):
            self.after(0, self._update_status, status_text)
            if "Done" in status_text or "Error" in status_text:
                self.modules_done += 1
                progress_value = (self.modules_done / total_modules) * 100
                self.after(0, self._update_progress_bar, progress_value)

        scanner = Scanner(target, progress_callback)
        self.last_scan_result = scanner.run_full_scan()
        self.after(0, self._on_scan_complete)

    def _on_scan_complete(self):
        self._populate_treeview(self.last_scan_result)
        self._update_status(f"Scan for {self.last_scan_target} complete.")
        self.start_btn.config(state=tk.NORMAL)
        self.export_btn.config(state=tk.NORMAL)

    def _populate_treeview(self, data: dict):
        self.clear_results()
        self.row_count = 0 
        for module_name, results in data.items():
            parent_node = self.tree.insert('', 'end', text=module_name, open=True, tags=('heading',))
            if isinstance(results, dict):
                for key, value in results.items():
                    self._insert_tree_data(parent_node, key, value)
            else:
                tag = 'evenrow' if self.row_count % 2 == 0 else 'oddrow'
                self.tree.insert(parent_node, 'end', text="Result", values=(str(results),), tags=(tag,))
                self.row_count += 1
    
    def _insert_tree_data(self, parent_node, key, value):
        tag = 'evenrow' if self.row_count % 2 == 0 else 'oddrow'
        self.row_count += 1

        if isinstance(value, dict):
            node = self.tree.insert(parent_node, 'end', text=key, open=False, tags=(tag,))
            for sub_key, sub_value in value.items():
                self._insert_tree_data(node, sub_key, sub_value)
        elif isinstance(value, list):
            node = self.tree.insert(parent_node, 'end', text=key, open=False, tags=(tag,))
            if not value:
                self.tree.item(node, values=("[Empty List]",))
            else:
                for i, item in enumerate(value):
                    self._insert_tree_data(node, f"[{i}]", item)
        else:
            self.tree.insert(parent_node, 'end', text=key, values=(str(value),), tags=(tag,))
    
    def export_pdf(self):
        if not self.last_scan_result:
            messagebox.showerror("Error", "No scan data available to export.")
            return
        filename = f"{self.last_scan_target.replace('.', '_')}_{int(time.time())}.pdf"
        out_path = os.path.join(REPORTS_DIR, filename)
        
        try:
            self._update_status(f"Generating PDF report at {out_path}...")
            build_pdf_report(self.last_scan_target, self.last_scan_result, out_path)
            messagebox.showinfo("Success", f"Report successfully saved to:\n{out_path}")
        except Exception as e:
            messagebox.showerror("PDF Export Error", f"Failed to generate report: {e}")
        finally:
            self._update_status("Ready")

    def _update_status(self, text: str):
        self.status_label.config(text=text)

    def _update_progress_bar(self, value: float):
        self.progress_bar['value'] = value

    def clear_results(self):
        for i in self.tree.get_children():
            self.tree.delete(i)

if __name__ == '__main__':
    app = ReconApp()
    app.mainloop()