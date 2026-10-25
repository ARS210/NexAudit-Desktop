"""
gui/app.py

NexAudit main window (Tkinter — ships with standard Python, no extra
install required). Ties together engagement management, interface
control, live scan results, the audit log, and report generation.
"""

from __future__ import annotations

import os
import tkinter as tk
import webbrowser
from datetime import datetime, date
from pathlib import Path
from tkinter import ttk, messagebox, simpledialog

from core import db
from core.interface_manager import InterfaceManager, ToolNotFoundError
from core.scan_session import ScanSession, ScanConfig
from core.parser import parse_airodump_csv
from core.report import generate_html_report
from version import APP_NAME, VERSION, AUTHOR, DEVELOPERS, LEGAL_NOTICE

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_PATH = BASE_DIR / "logs" / "audit.log"
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"

POLL_INTERVAL_MS = 2000


class EngagementDialog(simpledialog.Dialog):
    """Modal dialog to create a new engagement (authorization record)."""

    def body(self, master):
        labels = ["Engagement name*", "Client", "Authorized by*",
                  "Authorization reference", "Start date (YYYY-MM-DD)*", "End date (YYYY-MM-DD)"]
        self.entries = {}
        for i, label in enumerate(labels):
            ttk.Label(master, text=label).grid(row=i, column=0, sticky="w", pady=3)
            e = ttk.Entry(master, width=40)
            e.grid(row=i, column=1, pady=3)
            self.entries[label] = e
        self.entries["Start date (YYYY-MM-DD)*"].insert(0, date.today().isoformat())
        return self.entries["Engagement name*"]

    def validate(self):
        if not self.entries["Engagement name*"].get().strip():
            messagebox.showerror("Required", "Engagement name is required.")
            return False
        if not self.entries["Authorized by*"].get().strip():
            messagebox.showerror("Required", "You must record who authorized this assessment.")
            return False
        return True

    def apply(self):
        self.result = {
            "name": self.entries["Engagement name*"].get().strip(),
            "client": self.entries["Client"].get().strip(),
            "authorized_by": self.entries["Authorized by*"].get().strip(),
            "authorization_ref": self.entries["Authorization reference"].get().strip(),
            "start_date": self.entries["Start date (YYYY-MM-DD)*"].get().strip(),
            "end_date": self.entries["End date (YYYY-MM-DD)"].get().strip(),
        }


class NexAuditApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} {VERSION} — Wireless Security Assessment Toolkit")
        self.geometry("1180x720")
        self.minsize(980, 620)

        db.init_db()

        self.iface_manager: InterfaceManager | None = None
        self.active_engagement: dict | None = None
        self.monitor_iface: str | None = None
        self.scan_session: ScanSession | None = None
        self.scan_session_db_id: int | None = None

        self._build_layout()
        self._init_backend()
        self._refresh_engagement_label()
        self._poll_scan_results()

    # ---------------- backend init ----------------

    def _init_backend(self):
        try:
            self.iface_manager = InterfaceManager(audit_log_path=LOG_PATH)
        except ToolNotFoundError as e:
            messagebox.showwarning(
                "aircrack-ng suite not found",
                f"{e}\n\nThe GUI will still open, but scanning features are disabled "
                "until airmon-ng / airodump-ng are installed and on PATH."
            )
            self.iface_manager = None

    # ---------------- layout ----------------

    def _build_layout(self):
        self._build_menu()

        root_pane = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        root_pane.pack(fill=tk.BOTH, expand=True)

        # ---- left control panel ----
        left = ttk.Frame(root_pane, padding=10)
        root_pane.add(left, weight=1)

        ttk.Label(left, text="Engagement", font=("", 11, "bold")).pack(anchor="w")
        self.engagement_label = ttk.Label(left, text="No active engagement", foreground="#b91c1c",
                                           wraplength=260)
        self.engagement_label.pack(anchor="w", pady=(0, 6))
        ttk.Button(left, text="New Engagement…", command=self.on_new_engagement).pack(fill=tk.X)
        ttk.Button(left, text="Load Engagement…", command=self.on_load_engagement).pack(fill=tk.X, pady=(4, 12))

        ttk.Separator(left).pack(fill=tk.X, pady=8)

        ttk.Label(left, text="Wireless Interface", font=("", 11, "bold")).pack(anchor="w")
        self.iface_combo = ttk.Combobox(left, state="readonly", width=28)
        self.iface_combo.pack(fill=tk.X, pady=(4, 4))
        ttk.Button(left, text="Refresh Interfaces", command=self.on_refresh_interfaces).pack(fill=tk.X)

        self.monitor_btn = ttk.Button(left, text="Enable Monitor Mode", command=self.on_toggle_monitor)
        self.monitor_btn.pack(fill=tk.X, pady=(8, 0))
        self.monitor_status = ttk.Label(left, text="Monitor mode: off", foreground="#6b7280")
        self.monitor_status.pack(anchor="w", pady=(2, 12))

        ttk.Separator(left).pack(fill=tk.X, pady=8)

        ttk.Label(left, text="Scan", font=("", 11, "bold")).pack(anchor="w")
        self.scan_btn = ttk.Button(left, text="Start Scan", command=self.on_toggle_scan)
        self.scan_btn.pack(fill=tk.X, pady=(4, 4))
        self.scan_status = ttk.Label(left, text="Idle", foreground="#6b7280")
        self.scan_status.pack(anchor="w")

        ttk.Separator(left).pack(fill=tk.X, pady=8)

        ttk.Button(left, text="Generate Report…", command=self.on_generate_report).pack(fill=tk.X)
        ttk.Button(left, text="Open Reports Folder", command=self.on_open_reports).pack(fill=tk.X, pady=(4, 0))

        # ---- right main panel ----
        right = ttk.Frame(root_pane, padding=10)
        root_pane.add(right, weight=4)

        notebook = ttk.Notebook(right)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Access points tab
        ap_frame = ttk.Frame(notebook)
        notebook.add(ap_frame, text="Access Points")
        ap_cols = ("essid", "bssid", "channel", "power", "privacy", "cipher", "last_seen")
        self.ap_tree = ttk.Treeview(ap_frame, columns=ap_cols, show="headings")
        for col, width in zip(ap_cols, (200, 140, 60, 70, 90, 90, 150)):
            self.ap_tree.heading(col, text=col.replace("_", " ").title())
            self.ap_tree.column(col, width=width)
        self.ap_tree.pack(fill=tk.BOTH, expand=True)

        # Stations tab
        st_frame = ttk.Frame(notebook)
        notebook.add(st_frame, text="Client Stations")
        st_cols = ("mac", "associated_bssid", "power", "packets", "last_seen")
        self.st_tree = ttk.Treeview(st_frame, columns=st_cols, show="headings")
        for col, width in zip(st_cols, (150, 150, 70, 80, 150)):
            self.st_tree.heading(col, text=col.replace("_", " ").title())
            self.st_tree.column(col, width=width)
        self.st_tree.pack(fill=tk.BOTH, expand=True)

        # Audit log tab
        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text="Audit Log")
        self.log_text = tk.Text(log_frame, state="disabled", font=("Courier", 10))
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def _build_menu(self):
        menubar = tk.Menu(self)
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About NexAudit", command=self.on_about)
        help_menu.add_command(label="Legal Notice", command=self.on_legal)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menubar)

    # ---------------- engagement handlers ----------------

    def on_new_engagement(self):
        dlg = EngagementDialog(self, title="New Engagement")
        if getattr(dlg, "result", None):
            data = dlg.result
            eng = db.Engagement(
                id=None, name=data["name"], client=data["client"],
                authorized_by=data["authorized_by"],
                authorization_ref=data["authorization_ref"],
                start_date=data["start_date"], end_date=data["end_date"],
            )
            eng_id = db.create_engagement(eng)
            self.active_engagement = {**data, "id": eng_id}
            self._refresh_engagement_label()

    def on_load_engagement(self):
        rows = db.list_engagements()
        if not rows:
            messagebox.showinfo("No engagements", "No engagements found. Create one first.")
            return
        names = [f"{r['id']}: {r['name']} ({r['start_date']})" for r in rows]
        choice = simpledialog.askstring(
            "Load Engagement",
            "Available engagements:\n" + "\n".join(names) + "\n\nEnter engagement ID:"
        )
        if not choice:
            return
        try:
            eng_id = int(choice.strip())
        except ValueError:
            messagebox.showerror("Invalid", "Enter a numeric engagement ID.")
            return
        row = db.get_engagement(eng_id)
        if not row:
            messagebox.showerror("Not found", f"No engagement with ID {eng_id}.")
            return
        self.active_engagement = dict(row)
        self._refresh_engagement_label()

    def _refresh_engagement_label(self):
        if self.active_engagement:
            self.engagement_label.config(
                text=f"{self.active_engagement['name']} (ID {self.active_engagement['id']})",
                foreground="#15803d",
            )
        else:
            self.engagement_label.config(text="No active engagement", foreground="#b91c1c")

    # ---------------- interface handlers ----------------

    def on_refresh_interfaces(self):
        if not self.iface_manager:
            messagebox.showerror("Unavailable", "aircrack-ng suite is not installed.")
            return
        try:
            interfaces = self.iface_manager.list_interfaces()
        except Exception as e:
            messagebox.showerror("Error", f"Could not list interfaces:\n{e}")
            return
        names = [i.name for i in interfaces]
        self.iface_combo["values"] = names
        if names:
            self.iface_combo.current(0)
        else:
            messagebox.showinfo("No interfaces", "No wireless interfaces detected.")

    def on_toggle_monitor(self):
        if not self.iface_manager:
            messagebox.showerror("Unavailable", "aircrack-ng suite is not installed.")
            return
        iface = self.iface_combo.get()
        if not iface:
            messagebox.showwarning("Select interface", "Choose a wireless interface first.")
            return

        if self.monitor_iface:
            self.iface_manager.disable_monitor_mode(self.monitor_iface)
            self.monitor_iface = None
            self.monitor_status.config(text="Monitor mode: off", foreground="#6b7280")
            self.monitor_btn.config(text="Enable Monitor Mode")
        else:
            try:
                mon = self.iface_manager.enable_monitor_mode(iface)
            except Exception as e:
                messagebox.showerror("Error", f"Could not enable monitor mode:\n{e}")
                return
            self.monitor_iface = mon
            self.monitor_status.config(text=f"Monitor mode: on ({mon})", foreground="#15803d")
            self.monitor_btn.config(text="Disable Monitor Mode")

    # ---------------- scan handlers ----------------

    def on_toggle_scan(self):
        if not self.active_engagement:
            messagebox.showwarning(
                "No engagement",
                "Create or load an engagement before starting a scan.\n\n"
                "NexAudit ties every scan to a documented authorization."
            )
            return
        if not self.monitor_iface:
            messagebox.showwarning("Monitor mode required", "Enable monitor mode on an interface first.")
            return

        if self.scan_session and self.scan_session.is_running():
            self.scan_session.stop()
            if self.scan_session_db_id:
                db.record_scan_end(self.scan_session_db_id)
            self.scan_status.config(text="Idle", foreground="#6b7280")
            self.scan_btn.config(text="Start Scan")
        else:
            label = f"eng{self.active_engagement['id']}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            config = ScanConfig(
                monitor_interface=self.monitor_iface,
                output_dir=DATA_DIR / "scans",
                session_label=label,
            )
            self.scan_session = ScanSession(config, audit_log_path=LOG_PATH)
            self.scan_session.start()
            self.scan_session_db_id = db.record_scan_start(
                self.active_engagement["id"], self.monitor_iface, str(config.output_dir / label)
            )
            self.scan_status.config(text=f"Scanning ({label})", foreground="#15803d")
            self.scan_btn.config(text="Stop Scan")

    def _poll_scan_results(self):
        if self.scan_session and self.scan_session.is_running():
            aps, stations = parse_airodump_csv(self.scan_session.csv_path())
            self._populate_tree(self.ap_tree, aps, (
                "essid", "bssid", "channel", "power", "privacy", "cipher", "last_seen"
            ))
            self._populate_tree(self.st_tree, stations, (
                "mac", "associated_bssid", "power", "packets", "last_seen"
            ))
        self._refresh_log_view()
        self.after(POLL_INTERVAL_MS, self._poll_scan_results)

    @staticmethod
    def _populate_tree(tree: ttk.Treeview, rows, fields):
        tree.delete(*tree.get_children())
        for row in rows:
            values = [getattr(row, f) for f in fields]
            tree.insert("", tk.END, values=values)

    def _refresh_log_view(self):
        if not LOG_PATH.exists():
            return
        content = LOG_PATH.read_text(errors="replace")
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.insert(tk.END, content)
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")

    # ---------------- reporting ----------------

    def on_generate_report(self):
        if not self.active_engagement:
            messagebox.showwarning("No engagement", "Load or create an engagement first.")
            return
        if not self.scan_session:
            messagebox.showwarning("No scan data", "Run a scan before generating a report.")
            return

        aps, stations = parse_airodump_csv(self.scan_session.csv_path())
        out_path = REPORTS_DIR / f"NexAudit_report_{self.active_engagement['id']}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
        generate_html_report(self.active_engagement, aps, stations, out_path)
        messagebox.showinfo("Report generated", f"Report saved to:\n{out_path}")
        try:
            webbrowser.open(f"file://{out_path.resolve()}")
        except Exception:
            pass

    def on_open_reports(self):
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        try:
            webbrowser.open(f"file://{REPORTS_DIR.resolve()}")
        except Exception:
            messagebox.showinfo("Reports folder", str(REPORTS_DIR.resolve()))

    # ---------------- help ----------------

    def on_about(self):
        messagebox.showinfo(
            "About NexAudit",
            f"{APP_NAME} {VERSION}\nAuthor: {AUTHOR}\nDeveloped by: {DEVELOPERS}"
        )

    def on_legal(self):
        messagebox.showinfo("Legal Notice", LEGAL_NOTICE)


def run():
    app = NexAuditApp()
    app.mainloop()
