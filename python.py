"""
Citizen Help Portal - All Services (Single-file scaffold)
 - Tkinter GUI (Notebook tabs)
 - MySQL backend (create DB & tables)
 - OOP architecture: DatabaseManager, AuthManager, Module managers, NotificationManager, etc.
 - bcrypt password hashing
 - Multilanguage skeleton (English/Bengali)
 - AI Chatbot stub
 - OTP stub
 - Comments show where to integrate external services

Author: Generated scaffolding
"""
import os
import csv
import bcrypt
import mysql.connector
from datetime import datetime
from tkinter import *
from tkinter import ttk, messagebox, filedialog
import smtplib
from email.message import EmailMessage
import ssl
import random
import json

# ---------------- Configuration ----------------
DB_NAME = "citizen_portal_all"
DB_CONFIG = {"host": "localhost", "user": "root", "password": ""}  # adjust as needed

SMTP_CONFIG = {
    "enabled": False,
    "smtp_server": "smtp.example.com",
    "smtp_port": 465,
    "smtp_user": "your-email@example.com",
    "smtp_password": "password",
}

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123"

LANG = "en"  # 'en' or 'bn'

# --------------- Database Manager ----------------
class DatabaseManager:
    def __init__(self, cfg=None, db_name=None):
        self.cfg = cfg or DB_CONFIG
        self.db_name = db_name or DB_NAME
        self._ensure_db_and_tables()

    def connect(self, use_db=True):
        cfg = self.cfg.copy()
        if use_db:
            cfg["database"] = self.db_name
        return mysql.connector.connect(**cfg)

    def execute(self, query, params=None, fetch=False):
        conn = self.connect(use_db=True)
        cursor = conn.cursor()
        cursor.execute(query, params or ())
        if fetch:
            rows = cursor.fetchall()
            conn.close()
            return rows
        conn.commit()
        conn.close()
        return None

    def execute_no_db(self, query, params=None):
        conn = self.connect(use_db=False)
        cursor = conn.cursor()
        cursor.execute(query, params or ())
        conn.commit()
        conn.close()

    def _ensure_db_and_tables(self):
        # Create database
        try:
            self.execute_no_db(f"CREATE DATABASE IF NOT EXISTS {self.db_name}")
        except Exception as e:
            print("DB creation error:", e)
            raise

        # Create necessary tables
        conn = self.connect(use_db=True)
        cursor = conn.cursor()

        # citizens
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS citizens (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(150) NOT NULL,
                address VARCHAR(255),
                phone VARCHAR(30),
                nid VARCHAR(50),
                dob DATE,
                username VARCHAR(100) UNIQUE,
                password VARCHAR(255),
                role ENUM('Citizen','Officer','Admin') DEFAULT 'Citizen',
                email VARCHAR(255),
                created_at DATETIME
            )
        """)

        # reports (general complaints/service requests)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INT AUTO_INCREMENT PRIMARY KEY,
                citizen_id INT,
                citizen_name VARCHAR(150),
                category VARCHAR(100),
                sub_type VARCHAR(100),
                title VARCHAR(255),
                description TEXT,
                location VARCHAR(255),
                status VARCHAR(30) DEFAULT 'Pending',
                assigned_to INT,
                created_at DATETIME,
                updated_at DATETIME,
                FOREIGN KEY (citizen_id) REFERENCES citizens(id) ON DELETE SET NULL
            )
        """)

        # births & deaths
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS civil_registry (
                id INT AUTO_INCREMENT PRIMARY KEY,
                citizen_id INT,
                record_type ENUM('birth','death'),
                name VARCHAR(150),
                dob DATE,
                doc_path VARCHAR(255),
                created_at DATETIME,
                status VARCHAR(30) DEFAULT 'Pending'
            )
        """)

        # healthcare (appointments, e-health)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS health_appointments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                citizen_id INT,
                patient_name VARCHAR(150),
                facility VARCHAR(255),
                appointment_date DATETIME,
                doctor VARCHAR(150),
                status VARCHAR(30) DEFAULT 'Scheduled',
                created_at DATETIME
            )
        """)

        # education applications
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS education_applications (
                id INT AUTO_INCREMENT PRIMARY KEY,
                citizen_id INT,
                institution VARCHAR(255),
                program VARCHAR(255),
                application_data TEXT,
                status VARCHAR(50) DEFAULT 'Pending',
                created_at DATETIME
            )
        """)

        # housing payments / requests
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS housing_requests (
                id INT AUTO_INCREMENT PRIMARY KEY,
                citizen_id INT,
                request_type VARCHAR(100),
                details TEXT,
                status VARCHAR(30) DEFAULT 'Pending',
                created_at DATETIME
            )
        """)

        # employment / business
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS employment_applications (
                id INT AUTO_INCREMENT PRIMARY KEY,
                citizen_id INT,
                job_title VARCHAR(255),
                resume_path VARCHAR(255),
                status VARCHAR(50) DEFAULT 'Pending',
                created_at DATETIME
            )
        """)

        # transport (vehicle registration, fines)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transport_requests (
                id INT AUTO_INCREMENT PRIMARY KEY,
                citizen_id INT,
                request_type VARCHAR(100),
                vehicle_no VARCHAR(50),
                details TEXT,
                status VARCHAR(30) DEFAULT 'Pending',
                created_at DATETIME
            )
        """)

        # legal (police clearance, GD, court cases)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS legal_requests (
                id INT AUTO_INCREMENT PRIMARY KEY,
                citizen_id INT,
                request_type VARCHAR(100),
                details TEXT,
                status VARCHAR(30) DEFAULT 'Pending',
                created_at DATETIME
            )
        """)

        # finance (benefits, pensions)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS finance_requests (
                id INT AUTO_INCREMENT PRIMARY KEY,
                citizen_id INT,
                benefit_type VARCHAR(255),
                details TEXT,
                status VARCHAR(30) DEFAULT 'Pending',
                created_at DATETIME
            )
        """)

        # land records
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS land_records (
                id INT AUTO_INCREMENT PRIMARY KEY,
                citizen_id INT,
                record_type VARCHAR(100),
                details TEXT,
                record_file VARCHAR(255),
                created_at DATETIME
            )
        """)

        # environment & civic initiatives
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS civic_actions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                citizen_id INT,
                action_type VARCHAR(100),
                details TEXT,
                status VARCHAR(30) DEFAULT 'Pending',
                created_at DATETIME
            )
        """)

        # tech logs / e-governance
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tech_requests (
                id INT AUTO_INCREMENT PRIMARY KEY,
                citizen_id INT,
                request_type VARCHAR(100),
                details TEXT,
                status VARCHAR(30) DEFAULT 'Pending',
                created_at DATETIME
            )
        """)

        # notifications
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id INT AUTO_INCREMENT PRIMARY KEY,
                citizen_id INT,
                title VARCHAR(255),
                message TEXT,
                sent_at DATETIME
            )
        """)

        # audit logs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                action VARCHAR(255),
                details TEXT,
                created_at DATETIME
            )
        """)

        conn.commit()
        conn.close()

# ---------------- Security ----------------
class Security:
    @staticmethod
    def hash_password(password: str) -> str:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    @staticmethod
    def check_password(password: str, hashed: str) -> bool:
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception:
            return False

# ---------------- Notification Manager ----------------
class NotificationManager:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def send_popup(self, title, message):
        messagebox.showinfo(title, message)

    def save_notification(self, citizen_id, title, message):
        try:
            self.db.execute("INSERT INTO notifications (citizen_id, title, message, sent_at) VALUES (%s,%s,%s,%s)",
                            (citizen_id, title, message, datetime.now()))
        except Exception as e:
            print("Notify save error:", e)

    def send_email(self, to_email, subject, body):
        if not SMTP_CONFIG.get("enabled"):
            return False
        try:
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = SMTP_CONFIG["smtp_user"]
            msg["To"] = to_email
            msg.set_content(body)
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(SMTP_CONFIG["smtp_server"], SMTP_CONFIG["smtp_port"], context=context) as server:
                server.login(SMTP_CONFIG["smtp_user"], SMTP_CONFIG["smtp_password"])
                server.send_message(msg)
            return True
        except Exception as e:
            print("Email send error:", e)
            return False

# ---------------- Auth Manager ----------------
class AuthManager:
    def __init__(self, db: DatabaseManager, notifier: NotificationManager):
        self.db = db
        self.notifier = notifier
        self.ensure_default_admin()

    def ensure_default_admin(self):
        try:
            rows = self.db.execute("SELECT COUNT(*) FROM citizens WHERE role='Admin'", fetch=True)
            if rows and rows[0][0] == 0:
                hashed = Security.hash_password(DEFAULT_ADMIN_PASSWORD)
                self.db.execute("INSERT INTO citizens (name, username, password, role, created_at) VALUES (%s,%s,%s,%s,%s)",
                                ('Administrator', DEFAULT_ADMIN_USERNAME, hashed, 'Admin', datetime.now()))
                print("Default admin created:", DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD)
        except Exception as e:
            print("Default admin error:", e)

    def register(self, name, username, password, role='Citizen', address=None, phone=None, nid=None, dob=None, email=None):
        if not (name and username and password):
            raise ValueError("Name, username and password are required")
        hashed = Security.hash_password(password)
        try:
            self.db.execute("INSERT INTO citizens (name, address, phone, nid, dob, username, password, role, email, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                            (name, address, phone, nid, dob if dob else None, username, hashed, role, email, datetime.now()))
            return True
        except mysql.connector.IntegrityError:
            raise ValueError("Username already exists")

    def login(self, username, password):
        rows = self.db.execute("SELECT id, name, password, role, email FROM citizens WHERE username=%s", (username,), fetch=True)
        if not rows:
            return None
        user_id, name, hashed_pw, role, email = rows[0]
        if Security.check_password(password, hashed_pw):
            # Log audit
            try:
                self.db.execute("INSERT INTO audit_logs (user_id, action, details, created_at) VALUES (%s,%s,%s,%s)",
                                (user_id, 'login', f'User {username} logged in', datetime.now()))
            except Exception:
                pass
            return {"id": user_id, "username": username, "name": name, "role": role, "email": email}
        return None

    def otp_send_stub(self, phone_or_email):
        # Placeholder: integrate SMS gateway or email-based OTP
        code = random.randint(100000, 999999)
        print("OTP (stub):", code)
        return code

# ---------------- Module Managers (scaffolded) ----------------
class ReportManager:
    def __init__(self, db: DatabaseManager, notifier: NotificationManager):
        self.db = db
        self.notifier = notifier

    def submit_report(self, citizen_id, citizen_name, category, sub_type, title, description, location):
        if not (citizen_name and category and description and location):
            raise ValueError("Missing required fields")
        self.db.execute("INSERT INTO reports (citizen_id, citizen_name, category, sub_type, title, description, location, status, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        (citizen_id, citizen_name, category, sub_type, title, description, location, 'Pending', datetime.now()))
        # notify
        self.notifier.save_notification(citizen_id, "Report Submitted", f"Your report '{title}' has been submitted.")
        self.notifier.send_popup("Report Submitted", f"Report '{title}' submitted.")

    def list_all(self):
        return self.db.execute("SELECT id, citizen_id, citizen_name, category, sub_type, title, description, location, status, created_at FROM reports", fetch=True)

    def list_by_user(self, username):
        return self.db.execute("SELECT r.id, r.citizen_id, r.citizen_name, r.category, r.sub_type, r.title, r.description, r.location, r.status, r.created_at FROM reports r JOIN citizens c ON r.citizen_id=c.id WHERE c.username=%s", (username,), fetch=True)

    def update_status(self, report_id, status, admin_id=None):
        self.db.execute("UPDATE reports SET status=%s, updated_at=%s WHERE id=%s", (status, datetime.now(), report_id))
        # fetch citizen_id
        rows = self.db.execute("SELECT citizen_id, title FROM reports WHERE id=%s", (report_id,), fetch=True)
        if rows:
            citizen_id, title = rows[0]
            self.notifier.save_notification(citizen_id, "Report Status Updated", f"Your report '{title}' changed to {status}.")
            self.notifier.send_popup("Status Updated", f"Report #{report_id} status changed to {status}.")

    def delete_report(self, report_id):
        self.db.execute("DELETE FROM reports WHERE id=%s", (report_id,))

    def export_csv(self, rows, file_path):
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["id","citizen_id","citizen_name","category","sub_type","title","description","location","status","created_at"])
            for r in rows:
                # format date if necessary
                row = list(r)
                if isinstance(row[-1], datetime):
                    row[-1] = row[-1].strftime("%Y-%m-%d %H:%M:%S")
                writer.writerow(row)

# Additional managers can be added similarly. For brevity, we implement representative modules.

class CivilRegistryManager:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def submit_birth(self, citizen_id, name, dob, doc_path=None):
        self.db.execute("INSERT INTO civil_registry (citizen_id, record_type, name, dob, doc_path, created_at, status) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                        (citizen_id, 'birth', name, dob, doc_path, datetime.now(), 'Pending'))

    def submit_death(self, citizen_id, name, dob, doc_path=None):
        self.db.execute("INSERT INTO civil_registry (citizen_id, record_type, name, dob, doc_path, created_at, status) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                        (citizen_id, 'death', name, dob, doc_path, datetime.now(), 'Pending'))

    def list_records(self, citizen_id=None):
        if citizen_id:
            return self.db.execute("SELECT * FROM civil_registry WHERE citizen_id=%s", (citizen_id,), fetch=True)
        return self.db.execute("SELECT * FROM civil_registry", fetch=True)

class HealthManager:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def book_appointment(self, citizen_id, patient_name, facility, appointment_dt, doctor=None):
        self.db.execute("INSERT INTO health_appointments (citizen_id, patient_name, facility, appointment_date, doctor, status, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                        (citizen_id, patient_name, facility, appointment_dt, doctor, 'Scheduled', datetime.now()))

    def list_appointments(self, citizen_id=None):
        if citizen_id:
            return self.db.execute("SELECT * FROM health_appointments WHERE citizen_id=%s", (citizen_id,), fetch=True)
        return self.db.execute("SELECT * FROM health_appointments", fetch=True)

class EducationManager:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def submit_application(self, citizen_id, institution, program, app_data_json):
        self.db.execute("INSERT INTO education_applications (citizen_id, institution, program, application_data, status, created_at) VALUES (%s,%s,%s,%s,%s,%s)",
                        (citizen_id, institution, program, json.dumps(app_data_json), 'Pending', datetime.now()))

    def list_applications(self, citizen_id=None):
        if citizen_id:
            return self.db.execute("SELECT * FROM education_applications WHERE citizen_id=%s", (citizen_id,), fetch=True)
        return self.db.execute("SELECT * FROM education_applications", fetch=True)

# Other managers omitted for brevity: housing, employment, transport, legal, finance, land, environment, tech
# They would follow same pattern: insert/select/update tables created earlier.

# ---------------- AI Chatbot (Stub) ----------------
class AIChatbot:
    def __init__(self):
        pass

    def ask(self, user_text, lang='en'):
        # Placeholder stub: replace with actual AI integration (OpenAI / local model) as needed.
        # Return canned responses or use an AI API.
        if 'নিবন্ধন' in user_text or 'registration' in user_text.lower():
            return "আপনি কি জন্ম নিবন্ধন করতে চান? / Do you want to register birth?"
        if 'ভাড়া' in user_text or 'rent' in user_text.lower():
            return "For housing assistance, please provide your city and issue details."
        # simple echo
        return f"Chatbot (stub): You said -> {user_text}"

# ---------------- GUI Application ----------------
class CitizenPortalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Citizen Help Portal - All Services")
        self.root.geometry("1200x750")
        self.db = DatabaseManager()
        self.notifier = NotificationManager(self.db)
        self.auth = AuthManager(self.db, self.notifier)
        self.report_mgr = ReportManager(self.db, self.notifier)
        self.civil_mgr = CivilRegistryManager(self.db)
        self.health_mgr = HealthManager(self.db)
        self.edu_mgr = EducationManager(self.db)
        self.chatbot = AIChatbot()

        # Current user
        self.current_user = {"id": None, "username": None, "role": None, "name": None, "email": None}

        # Build UI frames
        self.login_frame = Frame(root)
        self.main_frame = Frame(root)
        self.build_login_frame()
        self.build_main_frame()

        self.show_frame(self.login_frame)

    def show_frame(self, frame):
        frame.pack(fill='both', expand=True)
        for f in (self.login_frame, self.main_frame):
            if f is not frame:
                f.pack_forget()

    # -------------- Login Frame --------------
    def build_login_frame(self):
        f = self.login_frame
        for widget in f.winfo_children():
            widget.destroy()
        Label(f, text="Citizen Help Portal", font=("Arial", 20)).pack(pady=10)
        frm = Frame(f)
        frm.pack(pady=10)
        Label(frm, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        self.login_user = Entry(frm); self.login_user.grid(row=0, column=1, padx=5, pady=5)
        Label(frm, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        self.login_pass = Entry(frm, show='*'); self.login_pass.grid(row=1, column=1, padx=5, pady=5)
        Button(frm, text="Login", command=self.login_action).grid(row=2, column=0, columnspan=2, pady=10)
        Button(frm, text="Register", command=self.open_register_window).grid(row=3, column=0, columnspan=2)
        Button(frm, text="Switch Language", command=self.toggle_language).grid(row=4, column=0, columnspan=2, pady=5)

    def toggle_language(self):
        global LANG
        LANG = 'bn' if LANG == 'en' else 'en'
        messagebox.showinfo("Language", f"Switched to {LANG}")
        # In a full app you'd re-render text labels per language

    def open_register_window(self):
        win = Toplevel(self.root)
        win.title("Register New User")
        frm = Frame(win); frm.pack(padx=10, pady=10)
        Label(frm, text="Name:").grid(row=0, column=0); e_name = Entry(frm); e_name.grid(row=0, column=1)
        Label(frm, text="Username:").grid(row=1, column=0); e_username = Entry(frm); e_username.grid(row=1, column=1)
        Label(frm, text="Password:").grid(row=2, column=0); e_password = Entry(frm, show='*'); e_password.grid(row=2, column=1)
        Label(frm, text="Phone:").grid(row=3, column=0); e_phone = Entry(frm); e_phone.grid(row=3, column=1)
        Label(frm, text="Email:").grid(row=4, column=0); e_email = Entry(frm); e_email.grid(row=4, column=1)
        Label(frm, text="Role:").grid(row=5, column=0); role_cb = ttk.Combobox(frm, values=["Citizen","Officer","Admin"], state='readonly'); role_cb.grid(row=5, column=1); role_cb.set("Citizen")
        def do_register():
            try:
                self.auth.register(e_name.get().strip(), e_username.get().strip(), e_password.get().strip(), role_cb.get(), address=None, phone=e_phone.get().strip(), email=e_email.get().strip())
                messagebox.showinfo("Success", "Registered. You can log in now.")
                win.destroy()
            except Exception as ex:
                messagebox.showerror("Error", str(ex))
        Button(frm, text="Create", command=do_register).grid(row=6, column=0, columnspan=2, pady=8)

    def login_action(self):
        username = self.login_user.get().strip()
        password = self.login_pass.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Enter credentials")
            return
        user = self.auth.login(username, password)
        if not user:
            messagebox.showerror("Error", "Invalid credentials")
            return
        self.current_user = user
        messagebox.showinfo("Welcome", f"Welcome {user['name']} ({user['role']})")
        self.show_frame(self.main_frame)
        # configure tabs based on role
        self.configure_tabs_for_role(user['role'])

    # -------------- Main frame (Notebook with many tabs) --------------
    def build_main_frame(self):
        f = self.main_frame
        for w in f.winfo_children():
            w.destroy()
        top = Frame(f)
        top.pack(fill='x')
        Label(top, text="Citizen Help Portal - All Services", font=("Arial", 16)).pack(side=LEFT, padx=10, pady=8)
        Button(top, text="Logout", command=self.logout).pack(side=RIGHT, padx=10)
        Button(top, text="Export Audit Logs", command=self.export_audit).pack(side=RIGHT)

        nb = ttk.Notebook(f)
        nb.pack(fill='both', expand=True, padx=10, pady=10)

        # create tabs
        self.tab_dashboard = Frame(nb); nb.add(self.tab_dashboard, text="Dashboard")
        self.tab_citizen = Frame(nb); nb.add(self.tab_citizen, text="Citizen Services")
        self.tab_complaints = Frame(nb); nb.add(self.tab_complaints, text="Complaints & Requests")
        self.tab_health = Frame(nb); nb.add(self.tab_health, text="Health")
        self.tab_education = Frame(nb); nb.add(self.tab_education, text="Education")
        self.tab_housing = Frame(nb); nb.add(self.tab_housing, text="Housing")
        self.tab_employment = Frame(nb); nb.add(self.tab_employment, text="Employment")
        self.tab_transport = Frame(nb); nb.add(self.tab_transport, text="Transport")
        self.tab_legal = Frame(nb); nb.add(self.tab_legal, text="Legal")
        self.tab_finance = Frame(nb); nb.add(self.tab_finance, text="Finance")
        self.tab_land = Frame(nb); nb.add(self.tab_land, text="Land & Property")
        self.tab_environment = Frame(nb); nb.add(self.tab_environment, text="Environment")
        self.tab_tech = Frame(nb); nb.add(self.tab_tech, text="E-Gov / Tech Support")
        self.tab_chatbot = Frame(nb); nb.add(self.tab_chatbot, text="AI Chatbot")
        self.tab_admin = Frame(nb); nb.add(self.tab_admin, text="Admin Tools")

        # Populate each tab
        self.build_dashboard_tab(self.tab_dashboard)
        self.build_citizen_tab(self.tab_citizen)
        self.build_complaints_tab(self.tab_complaints)
        self.build_health_tab(self.tab_health)
        self.build_education_tab(self.tab_education)
        self.build_housing_tab(self.tab_housing)
        self.build_employment_tab(self.tab_employment)
        self.build_transport_tab(self.tab_transport)
        self.build_legal_tab(self.tab_legal)
        self.build_finance_tab(self.tab_finance)
        self.build_land_tab(self.tab_land)
        self.build_environment_tab(self.tab_environment)
        self.build_tech_tab(self.tab_tech)
        self.build_chatbot_tab(self.tab_chatbot)
        self.build_admin_tab(self.tab_admin)

    def configure_tabs_for_role(self, role):
        # show/hide admin tab depending on role
        if role != 'Admin':
            # hide admin tools by removing the tab
            # for simplicity we won't delete tabs here; in production you'd hide or disable
            pass

    def logout(self):
        self.current_user = {"id": None, "username": None, "role": None, "name": None, "email": None}
        self.show_frame(self.login_frame)

    def export_audit(self):
        try:
            rows = self.db.execute("SELECT id, user_id, action, details, created_at FROM audit_logs", fetch=True)
            file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
            if not file_path:
                return
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                w = csv.writer(f)
                w.writerow(["id","user_id","action","details","created_at"])
                for r in rows:
                    w.writerow(r)
            messagebox.showinfo("Exported", f"Audit logs exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # -------------- Dashboard Tab --------------
    def build_dashboard_tab(self, frame):
        for w in frame.winfo_children(): w.destroy()
        Label(frame, text="Dashboard - Summary", font=("Arial", 14)).pack(anchor=W, padx=10, pady=6)
        stats_frame = Frame(frame); stats_frame.pack(fill='x', padx=10, pady=6)
        # Example stats
        def refresh_stats():
            try:
                total_citizens = self.db.execute("SELECT COUNT(*) FROM citizens", fetch=True)[0][0]
                total_reports = self.db.execute("SELECT COUNT(*) FROM reports", fetch=True)[0][0]
                pending_reports = self.db.execute("SELECT COUNT(*) FROM reports WHERE status='Pending'", fetch=True)[0][0]
                lbl_citizens.config(text=f"Citizens: {total_citizens}")
                lbl_reports.config(text=f"Total Reports: {total_reports}")
                lbl_pending.config(text=f"Pending Reports: {pending_reports}")
            except Exception as e:
                print("Stats error:", e)
        lbl_citizens = Label(stats_frame, text="Citizens: -"); lbl_citizens.pack(side=LEFT, padx=8)
        lbl_reports = Label(stats_frame, text="Total Reports: -"); lbl_reports.pack(side=LEFT, padx=8)
        lbl_pending = Label(stats_frame, text="Pending Reports: -"); lbl_pending.pack(side=LEFT, padx=8)
        Button(frame, text="Refresh", command=refresh_stats).pack(padx=10, pady=6)
        refresh_stats()

    # -------------- Citizen Tab --------------
    def build_citizen_tab(self, frame):
        for w in frame.winfo_children(): w.destroy()
        Label(frame, text="Citizen Management", font=("Arial", 14)).pack(anchor=W, padx=10, pady=6)
        frm = Frame(frame); frm.pack(padx=10, pady=8, anchor=W)
        Label(frm, text="Name:").grid(row=0, column=0); e_name = Entry(frm); e_name.grid(row=0, column=1)
        Label(frm, text="Address:").grid(row=1, column=0); e_address = Entry(frm); e_address.grid(row=1, column=1)
        Label(frm, text="Phone:").grid(row=2, column=0); e_phone = Entry(frm); e_phone.grid(row=2, column=1)
        Label(frm, text="NID:").grid(row=3, column=0); e_nid = Entry(frm); e_nid.grid(row=3, column=1)
        Label(frm, text="DOB (YYYY-MM-DD):").grid(row=4, column=0); e_dob = Entry(frm); e_dob.grid(row=4, column=1)
        Label(frm, text="Username:").grid(row=5, column=0); e_username = Entry(frm); e_username.grid(row=5, column=1)
        Label(frm, text="Password:").grid(row=6, column=0); e_password = Entry(frm, show='*'); e_password.grid(row=6, column=1)
        Label(frm, text="Role:").grid(row=7, column=0); role_cb = ttk.Combobox(frm, values=["Citizen","Officer","Admin"], state='readonly'); role_cb.grid(row=7, column=1); role_cb.set("Citizen")

        def add_citizen():
            try:
                self.auth.register(e_name.get().strip(), e_username.get().strip(), e_password.get().strip(), role_cb.get(), address=e_address.get().strip(), phone=e_phone.get().strip(), nid=e_nid.get().strip(), dob=e_dob.get().strip())
                messagebox.showinfo("Added", "Citizen added")
                e_name.delete(0,END); e_username.delete(0,END); e_password.delete(0,END)
            except Exception as ex:
                messagebox.showerror("Error", str(ex))
        Button(frm, text="Add Citizen", command=add_citizen).grid(row=8, column=0, columnspan=2, pady=8)

        # Search / Edit area
        search_frm = Frame(frame); search_frm.pack(padx=10, pady=8, anchor=W)
        Label(search_frm, text="Search Username:").grid(row=0, column=0); s_user = Entry(search_frm); s_user.grid(row=0, column=1)
        def search_user():
            uname = s_user.get().strip()
            if not uname: return
            rows = self.db.execute("SELECT id,name,address,phone,nid,dob,username,role,email FROM citizens WHERE username=%s", (uname,), fetch=True)
            if not rows:
                messagebox.showinfo("Not found", "No such user")
                return
            r = rows[0]
            messagebox.showinfo("Citizen", f"Name: {r[1]}\nPhone: {r[3]}\nNID: {r[4]}\nRole: {r[7]}\nEmail: {r[8]}")
        Button(search_frm, text="Search", command=search_user).grid(row=0, column=2, padx=6)

    # -------------- Complaints & Requests tab --------------
    def build_complaints_tab(self, frame):
        for w in frame.winfo_children(): w.destroy()
        Label(frame, text="Complaints & Service Requests", font=("Arial", 14)).pack(anchor=W, padx=10, pady=6)
        frm = Frame(frame); frm.pack(padx=10, pady=6, anchor=W)
        Label(frm, text="Name:").grid(row=0, column=0); e_name = Entry(frm); e_name.grid(row=0, column=1)
        Label(frm, text="Category:").grid(row=1, column=0); cat_cb = ttk.Combobox(frm, values=["Roads","Drainage","Water","Electricity","Gas","Corruption","Other"], state='readonly'); cat_cb.grid(row=1, column=1); cat_cb.set("Roads")
        Label(frm, text="Sub-type:").grid(row=2, column=0); subtype = Entry(frm); subtype.grid(row=2, column=1)
        Label(frm, text="Title:").grid(row=3, column=0); title_e = Entry(frm, width=60); title_e.grid(row=3, column=1)
        Label(frm, text="Description:").grid(row=4, column=0); desc_e = Text(frm, width=60, height=4); desc_e.grid(row=4, column=1)
        Label(frm, text="Location:").grid(row=5, column=0); loc_e = Entry(frm); loc_e.grid(row=5, column=1)

        def submit_complaint():
            name = e_name.get().strip() or self.current_user.get('name')
            if not name:
                messagebox.showerror("Error", "Name required")
                return
            try:
                self.report_mgr.submit_report(self.current_user.get('id'), name, cat_cb.get(), subtype.get().strip(), title_e.get().strip(), desc_e.get("1.0",END).strip(), loc_e.get().strip())
                messagebox.showinfo("Submitted", "Complaint submitted.")
                # clear
                title_e.delete(0,END); desc_e.delete('1.0',END); loc_e.delete(0,END)
            except Exception as e:
                messagebox.showerror("Error", str(e))
        Button(frm, text="Submit Complaint", command=submit_complaint).grid(row=6, column=0, columnspan=2, pady=8)

        # treeview for viewing reports (admin/officer)
        tree_frm = Frame(frame); tree_frm.pack(fill='both', expand=True, padx=10, pady=6)
        cols = ("ID","Citizen","Category","SubType","Title","Location","Status","Created")
        tree = ttk.Treeview(tree_frm, columns=cols, show='headings')
        for c in cols:
            tree.heading(c, text=c); tree.column(c, width=140)
        tree.pack(side=LEFT, fill='both', expand=True)
        sb = Scrollbar(tree_frm, orient=VERTICAL, command=tree.yview); tree.configure(yscrollcommand=sb.set); sb.pack(side=LEFT, fill='y')

        def refresh_reports():
            for row in tree.get_children(): tree.delete(row)
            rows = self.report_mgr.list_all() if self.current_user.get('role') in ('Admin','Officer') else self.report_mgr.list_by_user(self.current_user.get('username') or '')
            for r in rows:
                created = r[9].strftime("%Y-%m-%d %H:%M") if r[9] else ''
                tree.insert('',END, values=(r[0], r[2], r[3], r[4], r[5], r[7], r[8], created))
        Button(frame, text="Refresh Reports", command=refresh_reports).pack(pady=6)

    # -------------- Health Tab --------------
    def build_health_tab(self, frame):
        for w in frame.winfo_children(): w.destroy()
        Label(frame, text="Health Services", font=("Arial", 14)).pack(anchor=W, padx=10, pady=6)
        frm = Frame(frame); frm.pack(padx=10, pady=6, anchor=W)
        Label(frm, text="Patient Name:").grid(row=0, column=0); e_pname = Entry(frm); e_pname.grid(row=0, column=1)
        Label(frm, text="Facility:").grid(row=1, column=0); e_fac = Entry(frm); e_fac.grid(row=1, column=1)
        Label(frm, text="Appointment Date (YYYY-MM-DD HH:MM):").grid(row=2, column=0); e_dt = Entry(frm); e_dt.grid(row=2, column=1)
        Label(frm, text="Doctor (optional):").grid(row=3, column=0); e_doc = Entry(frm); e_doc.grid(row=3, column=1)
        def book():
            try:
                dt = datetime.strptime(e_dt.get().strip(), "%Y-%m-%d %H:%M")
                self.health_mgr.book_appointment(self.current_user.get('id'), e_pname.get().strip() or self.current_user.get('name'), e_fac.get().strip(), dt, e_doc.get().strip())
                messagebox.showinfo("Booked", "Appointment booked.")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        Button(frm, text="Book Appointment", command=book).grid(row=4, column=0, columnspan=2, pady=6)

    # -------------- Education Tab --------------
    def build_education_tab(self, frame):
        for w in frame.winfo_children(): w.destroy()
        Label(frame, text="Education Services", font=("Arial", 14)).pack(anchor=W, padx=10, pady=6)
        frm = Frame(frame); frm.pack(padx=10, pady=6)
        Label(frm, text="Institution:").grid(row=0, column=0); e_inst = Entry(frm); e_inst.grid(row=0, column=1)
        Label(frm, text="Program:").grid(row=1, column=0); e_prog = Entry(frm); e_prog.grid(row=1, column=1)
        Label(frm, text="Application Data (JSON):").grid(row=2, column=0); e_app = Text(frm, height=6, width=50); e_app.grid(row=2, column=1)
        def apply_edu():
            try:
                data = json.loads(e_app.get("1.0", END).strip() or "{}")
                self.edu_mgr.submit_application(self.current_user.get('id'), e_inst.get().strip(), e_prog.get().strip(), data)
                messagebox.showinfo("Submitted", "Application submitted.")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        Button(frm, text="Submit Application", command=apply_edu).grid(row=3, column=0, columnspan=2, pady=6)

    # -------------- Housing Tab --------------
    def build_housing_tab(self, frame):
        for w in frame.winfo_children(): w.destroy()
        Label(frame, text="Housing & Municipal Services", font=("Arial", 14)).pack(anchor=W, padx=10, pady=6)
        frm = Frame(frame); frm.pack(padx=10, pady=6)
        Label(frm, text="Request Type:").grid(row=0, column=0); rt = ttk.Combobox(frm, values=["Holding Tax","Water Bill","Waste Management","Road Repair"], state='readonly'); rt.grid(row=0, column=1); rt.set("Holding Tax")
        Label(frm, text="Details:").grid(row=1, column=0); det = Text(frm, height=5, width=50); det.grid(row=1, column=1)
        def submit_housing():
            try:
                self.db.execute("INSERT INTO housing_requests (citizen_id, request_type, details, status, created_at) VALUES (%s,%s,%s,%s,%s)",
                                (self.current_user.get('id'), rt.get(), det.get("1.0",END).strip(), 'Pending', datetime.now()))
                messagebox.showinfo("Submitted","Housing request submitted.")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        Button(frm, text="Submit Request", command=submit_housing).grid(row=2, column=0, columnspan=2, pady=6)

    # -------------- Employment Tab --------------
    def build_employment_tab(self, frame):
        for w in frame.winfo_children(): w.destroy()
        Label(frame, text="Employment & Business Support", font=("Arial", 14)).pack(anchor=W, padx=10, pady=6)
        frm=Frame(frame); frm.pack(padx=10, pady=6)
        Label(frm, text="Job Title / Program:").grid(row=0, column=0); e_job = Entry(frm); e_job.grid(row=0, column=1)
        Label(frm, text="Resume (path optional):").grid(row=1, column=0); e_cv = Entry(frm); e_cv.grid(row=1, column=1)
        def apply_job():
            try:
                self.db.execute("INSERT INTO employment_applications (citizen_id, job_title, resume_path, status, created_at) VALUES (%s,%s,%s,%s,%s)",
                                (self.current_user.get('id'), e_job.get().strip(), e_cv.get().strip() or None, 'Pending', datetime.now()))
                messagebox.showinfo("Applied","Application saved.")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        Button(frm, text="Submit Application", command=apply_job).grid(row=2, column=0, columnspan=2, pady=6)

    # -------------- Transport Tab --------------
    def build_transport_tab(self, frame):
        for w in frame.winfo_children(): w.destroy()
        Label(frame, text="Transport & Traffic", font=("Arial", 14)).pack(anchor=W, padx=10, pady=6)
        frm=Frame(frame); frm.pack(padx=10, pady=6)
        Label(frm, text="Request Type:").grid(row=0, column=0); cb = ttk.Combobox(frm, values=["Vehicle Registration","Driving License","Fine Payment","Traffic Complaint"], state='readonly'); cb.grid(row=0, column=1); cb.set("Vehicle Registration")
        Label(frm, text="Vehicle No (if any):").grid(row=1, column=0); vno = Entry(frm); vno.grid(row=1, column=1)
        Label(frm, text="Details:").grid(row=2, column=0); det = Text(frm, height=4, width=50); det.grid(row=2, column=1)
        def submit_trans():
            try:
                self.db.execute("INSERT INTO transport_requests (citizen_id, request_type, vehicle_no, details, status, created_at) VALUES (%s,%s,%s,%s,%s,%s)",
                                (self.current_user.get('id'), cb.get(), vno.get().strip() or None, det.get("1.0",END).strip(), 'Pending', datetime.now()))
                messagebox.showinfo("Submitted","Transport request submitted.")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        Button(frm, text="Submit", command=submit_trans).grid(row=3, column=0, columnspan=2, pady=6)

    # -------------- Legal Tab --------------
    def build_legal_tab(self, frame):
        for w in frame.winfo_children(): w.destroy()
        Label(frame, text="Law & Administrative Services", font=("Arial", 14)).pack(anchor=W, padx=10, pady=6)
        frm=Frame(frame); frm.pack(padx=10, pady=6)
        Label(frm, text="Request Type:").grid(row=0, column=0); cb = ttk.Combobox(frm, values=["Police Clearance","GD","Court Case Status","Legal Aid"], state='readonly'); cb.grid(row=0, column=1); cb.set("Police Clearance")
        Label(frm, text="Details:").grid(row=1, column=0); det = Text(frm, height=6, width=50); det.grid(row=1, column=1)
        def submit_legal():
            try:
                self.db.execute("INSERT INTO legal_requests (citizen_id, request_type, details, status, created_at) VALUES (%s,%s,%s,%s,%s)",
                                (self.current_user.get('id'), cb.get(), det.get("1.0",END).strip(), 'Pending', datetime.now()))
                messagebox.showinfo("Submitted","Legal request submitted.")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        Button(frm, text="Submit", command=submit_legal).grid(row=2, column=0, columnspan=2, pady=6)

    # -------------- Finance Tab --------------
    def build_finance_tab(self, frame):
        for w in frame.winfo_children(): w.destroy()
        Label(frame, text="Financial Services", font=("Arial", 14)).pack(anchor=W, padx=10, pady=6)
        frm=Frame(frame); frm.pack(padx=10, pady=6)
        Label(frm, text="Benefit Type:").grid(row=0, column=0); cb=ttk.Combobox(frm, values=["Pension","VGD","Old Age Allowance","Youth Loan"], state='readonly'); cb.grid(row=0, column=1); cb.set("Pension")
        Label(frm, text="Details:").grid(row=1, column=0); dt = Text(frm, height=5, width=50); dt.grid(row=1, column=1)
        def submit_fin():
            try:
                self.db.execute("INSERT INTO finance_requests (citizen_id, benefit_type, details, status, created_at) VALUES (%s,%s,%s,%s,%s)",
                                (self.current_user.get('id'), cb.get(), dt.get("1.0",END).strip(), 'Pending', datetime.now()))
                messagebox.showinfo("Submitted","Finance request submitted.")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        Button(frm, text="Submit", command=submit_fin).grid(row=2, column=0, columnspan=2, pady=6)

    # -------------- Land & Property Tab --------------
    def build_land_tab(self, frame):
        for w in frame.winfo_children(): w.destroy()
        Label(frame, text="Land & Property Services", font=("Arial", 14)).pack(anchor=W, padx=10, pady=6)
        frm = Frame(frame); frm.pack(padx=10, pady=6)
        Label(frm, text="Record Type:").grid(row=0, column=0); cb=ttk.Combobox(frm, values=["Mutation","Khatiyan","Land Tax","Complaint"], state='readonly'); cb.grid(row=0, column=1); cb.set("Mutation")
        Label(frm, text="Details:").grid(row=1, column=0); dt = Text(frm, height=5, width=50); dt.grid(row=1, column=1)
        def submit_land():
            try:
                self.db.execute("INSERT INTO land_records (citizen_id, record_type, details, record_file, created_at) VALUES (%s,%s,%s,%s,%s)", 
                                (self.current_user.get('id'), cb.get(), dt.get("1.0",END).strip(), None, datetime.now()))
                messagebox.showinfo("Submitted","Land record request submitted.")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        Button(frm, text="Submit", command=submit_land).grid(row=2, column=0, columnspan=2, pady=6)

    # -------------- Environment Tab --------------
    def build_environment_tab(self, frame):
        for w in frame.winfo_children(): w.destroy()
        Label(frame, text="Environment & Civic Actions", font=("Arial", 14)).pack(anchor=W, padx=10, pady=6)
        frm=Frame(frame); frm.pack(padx=10, pady=6)
        Label(frm, text="Action Type:").grid(row=0, column=0); cb=ttk.Combobox(frm, values=["Waste Management","Tree Plantation","Pollution Report","Eco Initiative"], state='readonly'); cb.grid(row=0, column=1); cb.set("Waste Management")
        Label(frm, text="Details:").grid(row=1, column=0); dt=Text(frm, height=5, width=50); dt.grid(row=1, column=1)
        def submit_env():
            try:
                self.db.execute("INSERT INTO civic_actions (citizen_id, action_type, details, status, created_at) VALUES (%s,%s,%s,%s,%s)", 
                                (self.current_user.get('id'), cb.get(), dt.get("1.0",END).strip(), 'Pending', datetime.now()))
                messagebox.showinfo("Submitted","Civic action request submitted.")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        Button(frm, text="Submit", command=submit_env).grid(row=2, column=0, columnspan=2, pady=6)

    # -------------- Tech / e-gov Tab --------------
    def build_tech_tab(self, frame):
        for w in frame.winfo_children(): w.destroy()
        Label(frame, text="Technology & E-Governance Support", font=("Arial", 14)).pack(anchor=W, padx=10, pady=6)
        frm=Frame(frame); frm.pack(padx=10, pady=6)
        Label(frm, text="Request Type:").grid(row=0, column=0); cb=ttk.Combobox(frm, values=["E-Signature","Document Scan","Cloud Backup","Mobile App Support"], state='readonly'); cb.grid(row=0, column=1); cb.set("E-Signature")
        Label(frm, text="Details:").grid(row=1, column=0); dt=Text(frm, width=50, height=5); dt.grid(row=1, column=1)
        def submit_tech():
            try:
                self.db.execute("INSERT INTO tech_requests (citizen_id, request_type, details, status, created_at) VALUES (%s,%s,%s,%s,%s)",
                                (self.current_user.get('id'), cb.get(), dt.get("1.0",END).strip(), 'Pending', datetime.now()))
                messagebox.showinfo("Submitted","Tech request submitted.")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        Button(frm, text="Submit", command=submit_tech).grid(row=2, column=0, columnspan=2, pady=6)

    # -------------- AI Chatbot Tab --------------
    def build_chatbot_tab(self, frame):
        for w in frame.winfo_children(): w.destroy()
        Label(frame, text="AI Chatbot (stub)", font=("Arial", 14)).pack(anchor=W, padx=10, pady=6)
        frm=Frame(frame); frm.pack(padx=10, pady=6)
        txt = Text(frm, height=12, width=90); txt.grid(row=0, column=0, columnspan=2)
        entry = Entry(frm, width=80); entry.grid(row=1, column=0, pady=6)
        def ask():
            q = entry.get().strip()
            if not q: return
            res = self.chatbot.ask(q, lang=LANG)
            txt.insert(END, f"You: {q}\nBot: {res}\n\n")
            entry.delete(0,END)
        Button(frm, text="Ask", command=ask).grid(row=1, column=1, padx=6)

    # -------------- Admin Tab --------------
    def build_admin_tab(self, frame):
        for w in frame.winfo_children(): w.destroy()
        Label(frame, text="Admin Tools", font=("Arial", 14)).pack(anchor=W, padx=10, pady=6)
        frm = Frame(frame); frm.pack(padx=10, pady=6, anchor=W)
        Button(frm, text="View All Reports", command=self.admin_view_reports).grid(row=0, column=0, padx=6, pady=6)
        Button(frm, text="Backup DB to CSV", command=self.admin_backup_csv).grid(row=0, column=1, padx=6, pady=6)
        Button(frm, text="Restore DB from CSV", command=self.admin_restore_csv).grid(row=0, column=2, padx=6, pady=6)

    def admin_view_reports(self):
        win = Toplevel(self.root)
        win.title("All Reports")
        cols = ("ID","Citizen","Category","SubType","Title","Location","Status","Created")
        tree = ttk.Treeview(win, columns=cols, show='headings')
        for c in cols:
            tree.heading(c, text=c); tree.column(c, width=140)
        tree.pack(side=LEFT, fill='both', expand=True)
        sb = Scrollbar(win, orient=VERTICAL, command=tree.yview); tree.configure(yscrollcommand=sb.set); sb.pack(side=LEFT, fill='y')
        rows = self.report_mgr.list_all()
        for r in rows:
            created = r[9].strftime("%Y-%m-%d %H:%M") if r[9] else ''
            tree.insert('',END, values=(r[0], r[2], r[3], r[4], r[5], r[7], r[8], created))

    def admin_backup_csv(self):
        folder = filedialog.askdirectory()
        if not folder:
            return
        try:
            # export citizens
            citizens = self.db.execute("SELECT id,name,address,phone,nid,dob,username,password,role,email,created_at FROM citizens", fetch=True)
            reports = self.db.execute("SELECT id,citizen_id,citizen_name,category,sub_type,title,description,location,status,created_at FROM reports", fetch=True)
            cfile = os.path.join(folder, 'citizens_backup.csv')
            rfile = os.path.join(folder, 'reports_backup.csv')
            with open(cfile, 'w', newline='', encoding='utf-8') as f:
                w = csv.writer(f); w.writerow(["id","name","address","phone","nid","dob","username","password","role","email","created_at"])
                for r in citizens: w.writerow(r)
            with open(rfile, 'w', newline='', encoding='utf-8') as f:
                w = csv.writer(f); w.writerow(["id","citizen_id","citizen_name","category","sub_type","title","description","location","status","created_at"])
                for r in reports:
                    row = list(r)
                    if isinstance(row[-1], datetime):
                        row[-1] = row[-1].strftime("%Y-%m-%d %H:%M:%S")
                    w.writerow(row)
            messagebox.showinfo("Backup", f"Backups created:\n{cfile}\n{rfile}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def admin_restore_csv(self):
        folder = filedialog.askdirectory()
        if not folder:
            return
        if not messagebox.askyesno("Confirm", "This will DELETE existing data and restore from backups. Continue?"):
            return
        try:
            cfile = os.path.join(folder, 'citizens_backup.csv')
            rfile = os.path.join(folder, 'reports_backup.csv')
            if not os.path.exists(cfile) or not os.path.exists(rfile):
                messagebox.showerror("Error", "Backup files not found")
                return
            conn = self.db.connect()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM reports"); cursor.execute("DELETE FROM citizens"); conn.commit()
            with open(cfile, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cursor.execute("INSERT INTO citizens (id,name,address,phone,nid,dob,username,password,role,email,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                                   (row['id'],row['name'],row['address'],row['phone'],row['nid'],row['dob'] or None,row['username'],row['password'],row['role'],row['email'], row.get('created_at') or None))
            with open(rfile, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    dt = None
                    if row.get('created_at'):
                        try: dt = datetime.strptime(row['created_at'],'%Y-%m-%d %H:%M:%S')
                        except: dt = None
                    cursor.execute("INSERT INTO reports (id,citizen_id,citizen_name,category,sub_type,title,description,location,status,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                                   (row['id'], row['citizen_id'] or None, row['citizen_name'], row['category'], row['sub_type'], row['title'], row['description'], row['location'], row['status'], dt))
            conn.commit(); conn.close()
            messagebox.showinfo("Restored", "Data restored from backup")
        except Exception as e:
            messagebox.showerror("Error", str(e))

# ---------------- Run App ----------------
def main():
    root = Tk()
    app = CitizenPortalApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
