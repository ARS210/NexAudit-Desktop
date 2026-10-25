# NexAudit v1.0.0

**Author:** NexApp
**Developed by:** Arabi Islam x MR. ARX

A Linux GUI for **authorized** Wi-Fi security assessments. NexAudit wraps
the aircrack-ng suite (`airmon-ng`, `airodump-ng`) to manage wireless
interfaces, run passive scans, and produce audit-ready reports — with
every scan tied to a documented "engagement" (authorization record).

> ⚠️ **Legal notice**: Use NexAudit only on networks you own or have
> explicit written authorization to test. Unauthorized access to
> computer networks is illegal in most jurisdictions. This tool does
> not include any cracking, deauthentication, or unauthorized-access
> features — it is a passive scanning and reporting toolkit.

---

## 1. Project layout

```
NexAudit/
├── main.py                    # entry point
├── version.py                 # app metadata
├── setup.sh                   # dependency checker/installer
├── requirements.txt
├── nexaudit-sudoers.example    # scoped privilege delegation example
├── core/
│   ├── db.py                  # SQLite engagement/scope/scan tracking
│   ├── interface_manager.py   # airmon-ng wrapper + audit logging
│   ├── scan_session.py        # airodump-ng process management
│   ├── parser.py              # airodump-ng CSV parser
│   └── report.py              # HTML report generator
├── gui/
│   └── app.py                 # Tkinter GUI
├── data/                      # SQLite DB + scan CSVs (created at runtime)
├── logs/                      # audit.log (created at runtime)
└── reports/                   # generated HTML reports
```

---

## 2. Requirements

- Linux (tested target: Debian/Ubuntu/Kali-based distros)
- Python 3.10+
- `python3-tk` (Tkinter — the GUI toolkit; ships as a separate OS package)
- The **aircrack-ng suite**: `airmon-ng`, `airodump-ng`
- A wireless adapter that supports **monitor mode**

No third-party Python packages are required — NexAudit uses only the
standard library.

---

## 3. Setup

```bash
cd NexAudit
chmod +x setup.sh
./setup.sh
```

`setup.sh` checks for `python3`, `airmon-ng`, `airodump-ng`, and the
`tkinter` module, and offers to install missing ones via `apt` on
Debian/Ubuntu/Kali. To install manually on any apt-based system:

```bash
sudo apt-get update
sudo apt-get install aircrack-ng python3-tk
```

---

## 4. Privilege model (important)

**Do not run the whole GUI as root.** Monitor-mode toggling and
`airodump-ng` need elevated privileges, but the rest of the app
(SQLite writes, report generation, the UI itself) does not.

Two supported approaches:

**Option A — scoped sudoers entry (simplest for local testing)**
```bash
sudo visudo -f /etc/sudoers.d/nexaudit
# paste the contents of nexaudit-sudoers.example, replacing <youruser>
```
Then launch NexAudit normally as your user; when the sudoers rule is
in place you can run the whole app via `sudo -E python3 main.py` for
testing, or adapt `core/interface_manager.py` / `core/scan_session.py`
to prepend `sudo` to just the two privileged commands.

**Option B — pkexec / polkit (more GUI-native)**
Write a small polkit policy authorizing `airmon-ng`/`airodump-ng` for
your user, and prepend `pkexec` to those two commands instead of
`sudo`. This gives a graphical auth prompt per action instead of a
standing NOPASSWD grant.

For quick local testing, the simplest path is:
```bash
sudo python3 main.py
```
(NexAudit will print a warning if it detects it's running as root —
that's expected for this quick-start path, but Option A/B above is
recommended before using it on a real assessment.)

---

## 5. Running NexAudit

```bash
python3 main.py
```

On first launch NexAudit will:
1. Create `data/nexaudit.db` (SQLite) if it doesn't exist.
2. Open the main window.

### Typical workflow

1. **Help → Legal Notice** — review the usage policy.
2. **New Engagement…** — record what you're authorized to test:
   engagement name, who authorized it, an authorization reference
   (e.g. a signed scope-of-work number), and start/end dates. This
   is required before any scan can start.
3. **Refresh Interfaces** — lists detected wireless adapters via
   `airmon-ng`.
4. Select an interface → **Enable Monitor Mode**.
5. **Start Scan** — launches `airodump-ng` in the background; the
   Access Points and Client Stations tabs populate live (polled every
   2 seconds from the CSV output).
6. **Stop Scan** when done.
7. **Generate Report…** — writes a self-contained HTML report to
   `reports/`, tagged with the engagement's authorization metadata,
   and opens it in your browser.
8. The **Audit Log** tab shows every privileged command NexAudit has
   run, with timestamps — useful for chain-of-custody documentation.

---

## 6. Testing without wireless hardware

You can exercise everything except live scanning without a wireless
adapter or root:

```bash
# 1. Sanity-check all modules compile
python3 -m py_compile version.py core/*.py gui/app.py main.py

# 2. Exercise the database layer
python3 - <<'PY'
from core import db
db.init_db()
eng = db.Engagement(
    id=None, name="Demo Audit", client="Acme Inc",
    authorized_by="Jane CISO", authorization_ref="SOW-001",
    start_date="2026-07-28", end_date="2026-07-30",
)
eid = db.create_engagement(eng)
print("Created engagement:", dict(db.get_engagement(eid)))
PY

# 3. Exercise the CSV parser + report generator against a sample file
#    (write any airodump-ng-format CSV to data/sample_scan-01.csv, or
#    generate one from a real scan later) then:
python3 - <<'PY'
from pathlib import Path
from core.parser import parse_airodump_csv
from core.report import generate_html_report

aps, stations = parse_airodump_csv(Path("data/sample_scan-01.csv"))
print(f"{len(aps)} APs, {len(stations)} stations parsed")

engagement = {"id": 1, "name": "Demo Audit", "client": "Acme Inc",
              "authorized_by": "Jane CISO", "authorization_ref": "SOW-001",
              "start_date": "2026-07-28", "end_date": "2026-07-30"}
out = generate_html_report(engagement, aps, stations, Path("reports/demo.html"))
print("Report:", out)
PY
```

Open `reports/demo.html` in a browser to confirm formatting.

### Testing with real hardware (once you're ready for a live scan)

1. Confirm your adapter supports monitor mode: `iw list` → look for
   `* monitor` under supported interface modes.
2. Run `./setup.sh` to confirm `airmon-ng`/`airodump-ng` are installed.
3. Launch NexAudit (`sudo python3 main.py`, or your sudoers/pkexec
   setup), create an engagement scoped to a network **you own** (e.g.
   your home router), and run through the workflow in Section 5.
4. Check `logs/audit.log` afterward — it should show every
   `airmon-ng`/`airodump-ng` invocation with a timestamp.

---

## 7. What NexAudit deliberately does NOT do

- No packet injection, deauthentication, or handshake-capture triggers
- No WEP/WPA key cracking or password/wordlist handling
- No MAC spoofing helpers
- No bypass of captive portals, WPS PIN attacks, or similar

NexAudit's scope is passive reconnaissance (scan → observe → report)
plus the process/scope hygiene (engagement tracking, audit logging)
that a real assessment needs around that. If your engagement's rules
of engagement call for active attack techniques, those need to be run
directly via the underlying aircrack-ng suite (or other authorized
tooling) under your own documented authorization — outside this GUI.

---

## 8. License / attribution

NexAudit v1.0.0 — © NexApp. Developed by Arabi Islam x MR. ARX.
"# NexAudit-Desktop" 
"# NexAudit-Desktop" 
"# NexAudit-Desktop" 
