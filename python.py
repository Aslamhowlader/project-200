"""
Citizen Help Portal - Full Application (Tkinter + MySQL)
Features included:
- MySQL database setup (creates DB and tables)
- User registration (Citizen/Officer/Admin) with bcrypt password hashing
- Role-based login and interface
- Submit/view/update/delete reports
- CSV export, backup (CSV per table) and restore (from CSV files)
- Notification popup and optional email notifications

Before running:
- Install required packages: pip install mysql-connector-python bcrypt
- Configure MySQL server and update DB_CONFIG if needed
- Optional: configure SMTP settings for email notifications

Run: python citizen_portal_full.py
"""

import os
import csv
import bcrypt
import mysql.connector
from datetime import datetime
from tkinter import *
from tkinter import ttk, messagebox, filedialog
from email.message import EmailMessage
import smtplib
import ssl

# ===================== Configuration =====================
DB_NAME = "citizen_portal"
DB_CONFIG = {"host": "localhost", "user": "root", "password": ""}
# Optional: SMTP settings for email notifications. Fill these to enable email sending.
SMTP_CONFIG = {
    "enabled": False,
    "smtp_server": "smtp.example.com",
    "smtp_port": 465,
    "smtp_user": "your-email@example.com",
    "smtp_password": "password",
}

# ===================== Database Utilities =====================

def connect_db(db_name=None):
    cfg = DB_CONFIG.copy()
    if db_name:
        cfg["database"] = db_name
    return mysql.connector.connect(**cfg)


def run_query(query, params=None, fetch=False):
    conn = connect_db(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(query, params or ())
    if fetch:
        rows = cursor.fetchall()
        conn.close()
        return rows
    conn.commit()
    conn.close()


def create_database_and_tables():
    # Create database if not exists
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
    conn.close()

    # Create tables
    conn = connect_db(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS citizens (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            address VARCHAR(255),
            phone VARCHAR(20),
            nid VARCHAR(50),
            dob DATE,
            username VARCHAR(100) UNIQUE,
            password VARCHAR(255),
            role ENUM('Citizen','Officer','Admin') DEFAULT 'Citizen',
            email VARCHAR(255)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INT AUTO_INCREMENT PRIMARY KEY,
            citizen_id INT,
            citizen_name VARCHAR(100),
            problem_type VARCHAR(50),
            description TEXT,
            location VARCHAR(255),
            status VARCHAR(20) DEFAULT 'Pending',
            report_date DATETIME,
            FOREIGN KEY (citizen_id) REFERENCES citizens(id) ON DELETE SET NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            citizen_id INT,
            report_id INT,
            message TEXT,
            sent_at DATETIME
        )
    """)

    conn.commit()
    conn.close()


# ===================== Security Helpers =====================

def hash_password(plain_text_password: str) -> bytes:
    return bcrypt.hashpw(plain_text_password.encode('utf-8'), bcrypt.gensalt())


def check_password(plain_text_password: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(plain_text_password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False


# ===================== Email Notification =====================

def send_email(to_email: str, subject: str, body: str) -> bool:
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


# ===================== App Logic =====================

create_database_and_tables()

# ===================== Tkinter GUI =====================
root = Tk()
root.title("Citizen Help Portal")
root.geometry("1100x700")

# --------------------- Frames ---------------------
login_frame = Frame(root)
register_frame = Frame(root)
main_frame = Frame(root)

# --------------------- Shared Widgets ---------------------
# Treeview for reports
columns = ("ID", "CitizenID", "Name", "Problem", "Description", "Location", "Status", "Date")
tree = ttk.Treeview(main_frame, columns=columns, show='headings')
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=140)

# Vertical scrollbar for tree
tree_scroll = Scrollbar(main_frame, orient=VERTICAL, command=tree.yview)
tree.configure(yscrollcommand=tree_scroll.set)

# --------------------- Login UI ---------------------
Label(login_frame, text="Login", font=(None, 16)).grid(row=0, column=0, columnspan=2, pady=10)
Label(login_frame, text="Username:").grid(row=1, column=0, sticky=E, padx=5, pady=5)
entry_login_user = Entry(login_frame)
entry_login_user.grid(row=1, column=1, padx=5, pady=5)
Label(login_frame, text="Password:").grid(row=2, column=0, sticky=E, padx=5, pady=5)
entry_login_pass = Entry(login_frame, show='*')
entry_login_pass.grid(row=2, column=1, padx=5, pady=5)

btn_login = Button(login_frame, text="Login")
btn_login.grid(row=3, column=0, columnspan=2, pady=10)

Label(login_frame, text="Don't have an account?").grid(row=4, column=0, columnspan=1)
btn_to_register = Button(login_frame, text="Register", command=lambda: switch_frame(register_frame))
btn_to_register.grid(row=4, column=1)

# --------------------- Register UI ---------------------
Label(register_frame, text="Register New User", font=(None, 16)).grid(row=0, column=0, columnspan=2, pady=10)
Label(register_frame, text="Name:").grid(row=1, column=0, sticky=E)
entry_reg_name = Entry(register_frame)
entry_reg_name.grid(row=1, column=1, padx=5, pady=5)

Label(register_frame, text="Address:").grid(row=2, column=0, sticky=E)
entry_reg_address = Entry(register_frame)
entry_reg_address.grid(row=2, column=1, padx=5, pady=5)

Label(register_frame, text="Phone:").grid(row=3, column=0, sticky=E)
entry_reg_phone = Entry(register_frame)
entry_reg_phone.grid(row=3, column=1, padx=5, pady=5)

Label(register_frame, text="NID:").grid(row=4, column=0, sticky=E)
entry_reg_nid = Entry(register_frame)
entry_reg_nid.grid(row=4, column=1, padx=5, pady=5)

Label(register_frame, text="DOB (YYYY-MM-DD):").grid(row=5, column=0, sticky=E)
entry_reg_dob = Entry(register_frame)
entry_reg_dob.grid(row=5, column=1, padx=5, pady=5)

Label(register_frame, text="Email (optional):").grid(row=6, column=0, sticky=E)
entry_reg_email = Entry(register_frame)
entry_reg_email.grid(row=6, column=1, padx=5, pady=5)

Label(register_frame, text="Username:").grid(row=7, column=0, sticky=E)
entry_reg_username = Entry(register_frame)
entry_reg_username.grid(row=7, column=1, padx=5, pady=5)

Label(register_frame, text="Password:").grid(row=8, column=0, sticky=E)
entry_reg_password = Entry(register_frame, show='*')
entry_reg_password.grid(row=8, column=1, padx=5, pady=5)

Label(register_frame, text="Role:").grid(row=9, column=0, sticky=E)
combo_reg_role = ttk.Combobox(register_frame, values=["Citizen", "Officer", "Admin"], state='readonly')
combo_reg_role.grid(row=9, column=1, padx=5, pady=5)
combo_reg_role.set("Citizen")

btn_register = Button(register_frame, text="Create Account")
btn_register.grid(row=10, column=0, columnspan=2, pady=10)

btn_back_to_login = Button(register_frame, text="Back to Login", command=lambda: switch_frame(login_frame))
btn_back_to_login.grid(row=11, column=0, columnspan=2)

# --------------------- Main UI ---------------------

# Top: Submit report frame
frame_submit = LabelFrame(main_frame, text="Submit Report", padx=10, pady=10)
frame_submit.pack(fill='x', padx=10, pady=5)

Label(frame_submit, text="Name:").grid(row=0, column=0)
entry_name = Entry(frame_submit, width=30)
entry_name.grid(row=0, column=1)

Label(frame_submit, text="Problem Type:").grid(row=1, column=0)
combo_problem = ttk.Combobox(frame_submit, values=["Health", "Corruption", "Extortion", "Other"], width=28)
combo_problem.grid(row=1, column=1)

Label(frame_submit, text="Description:").grid(row=2, column=0)
text_desc = Text(frame_submit, width=60, height=3)
text_desc.grid(row=2, column=1)

Label(frame_submit, text="Location:").grid(row=3, column=0)
entry_location = Entry(frame_submit, width=30)
entry_location.grid(row=3, column=1)

btn_submit_report = Button(frame_submit, text="Submit Report")
btn_submit_report.grid(row=4, column=0, pady=5)

btn_clear_form = Button(frame_submit, text="Clear Form")
btn_clear_form.grid(row=4, column=1, pady=5)

# Middle: View / Controls
frame_view = LabelFrame(main_frame, text="View Reports", padx=10, pady=10)
frame_view.pack(fill='x', padx=10, pady=5)

Label(frame_view, text="Enter Your Username:").grid(row=0, column=0)
entry_view_username = Entry(frame_view, width=30)
entry_view_username.grid(row=0, column=1)

btn_view_my = Button(frame_view, text="View My Reports")
btn_view_my.grid(row=0, column=2, padx=5)

btn_view_all = Button(frame_view, text="View All Reports (Admin)")
btn_view_all.grid(row=0, column=3, padx=5)

# Tree and scrollbar packing
tree.pack(side=LEFT, fill='both', expand=True, padx=(10,0), pady=10)
tree_scroll.pack(side=LEFT, fill='y')

# Admin Controls frame
frame_admin = LabelFrame(main_frame, text="Admin Controls", padx=10, pady=10)
frame_admin.pack(fill='x', padx=10, pady=5)

combo_status = ttk.Combobox(frame_admin, values=["Pending", "In Progress", "Resolved"], width=20)
combo_status.grid(row=0, column=0, padx=5, pady=5)
btn_update_status = Button(frame_admin, text="Update Status")
btn_update_status.grid(row=0, column=1, padx=5, pady=5)

btn_delete = Button(frame_admin, text="Delete Selected")
btn_delete.grid(row=0, column=2, padx=5, pady=5)

btn_export = Button(frame_admin, text="Export CSV")
btn_export.grid(row=0, column=3, padx=5, pady=5)

btn_backup = Button(frame_admin, text="Backup Data (CSV)")
btn_backup.grid(row=0, column=4, padx=5, pady=5)

btn_restore = Button(frame_admin, text="Restore Data (CSV)")
btn_restore.grid(row=0, column=5, padx=5, pady=5)

combo_filter_status = ttk.Combobox(frame_admin, values=["Pending", "In Progress", "Resolved"], width=20)
combo_filter_status.grid(row=1, column=0, padx=5, pady=5)
btn_filter = Button(frame_admin, text="Filter by Status")
btn_filter.grid(row=1, column=1, padx=5, pady=5)

combo_search_problem = ttk.Combobox(frame_admin, values=["Health", "Corruption", "Extortion", "Other"], width=20)
combo_search_problem.grid(row=1, column=2, padx=5, pady=5)
btn_search = Button(frame_admin, text="Search by Problem")
btn_search.grid(row=1, column=3, padx=5, pady=5)

btn_sort = Button(frame_admin, text="Sort by Date")
btn_sort.grid(row=2, column=0, padx=5, pady=5)

# Bottom: Logout
btn_logout = Button(main_frame, text="Logout")
btn_logout.pack(pady=5)

# --------------------- Helper Functions ---------------------
current_user = {"id": None, "username": None, "role": None, "name": None, "email": None}


def switch_frame(frame_to_show):
    for f in (login_frame, register_frame, main_frame):
        f.pack_forget()
    frame_to_show.pack(fill='both', expand=True)


def clear_tree():
    for r in tree.get_children():
        tree.delete(r)


def format_row(row):
    # row: (id, citizen_id, citizen_name, problem_type, description, location, status, report_date)
    row = list(row)
    if row[7] and isinstance(row[7], datetime):
        row[7] = row[7].strftime('%Y-%m-%d %H:%M')
    return row


# --------------------- Core Features ---------------------

def register_user():
    name = entry_reg_name.get().strip()
    address = entry_reg_address.get().strip()
    phone = entry_reg_phone.get().strip()
    nid = entry_reg_nid.get().strip()
    dob = entry_reg_dob.get().strip()
    email = entry_reg_email.get().strip()
    username = entry_reg_username.get().strip()
    password = entry_reg_password.get().strip()
    role = combo_reg_role.get().strip() or 'Citizen'

    if not (name and username and password):
        messagebox.showerror("Error", "Name, username and password are required")
        return

    hashed = hash_password(password)

    try:
        conn = connect_db(DB_NAME)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO citizens (name, address, phone, nid, dob, username, password, role, email) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (name, address, phone, nid, dob if dob else None, username, hashed.decode('utf-8'), role, email)
        )
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "User registered successfully. You can log in now.")
        switch_frame(login_frame)
    except mysql.connector.IntegrityError:
        messagebox.showerror("Error", "Username already exists")
    except Exception as e:
        messagebox.showerror("Error", f"Registration failed: {e}")


def login_user():
    username = entry_login_user.get().strip()
    password = entry_login_pass.get().strip()

    if not (username and password):
        messagebox.showerror("Error", "Enter username and password")
        return

    try:
        conn = connect_db(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, password, role, email FROM citizens WHERE username=%s", (username,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            messagebox.showerror("Error", "No such user. Please register.")
            return

        user_id, name, hashed_pw, role, email = row
        if check_password(password, hashed_pw):
            current_user.update({"id": user_id, "username": username, "role": role, "name": name, "email": email})
            messagebox.showinfo("Welcome", f"Logged in as {username} ({role})")
            configure_ui_for_role()
            switch_frame(main_frame)
        else:
            messagebox.showerror("Error", "Incorrect password")
    except Exception as e:
        messagebox.showerror("Error", f"Login error: {e}")


def configure_ui_for_role():
    role = current_user.get('role')
    if role == 'Admin':
        # show admin controls
        btn_view_my.grid_remove()
        btn_view_all.grid()
        btn_update_status.grid()
        btn_delete.grid()
        btn_export.grid()
        btn_backup.grid()
        btn_restore.grid()
        btn_filter.grid()
        btn_search.grid()
        btn_sort.grid()
    elif role == 'Officer':
        # officer can see all but not backup/restore
        btn_view_my.grid_remove()
        btn_view_all.grid()
        btn_update_status.grid()
        btn_delete.grid_remove()
        btn_export.grid()
        btn_backup.grid_remove()
        btn_restore.grid_remove()
        btn_filter.grid()
        btn_search.grid()
        btn_sort.grid()
    else:
        # Citizen
        btn_view_my.grid()
        btn_view_all.grid_remove()
        btn_update_status.grid_remove()
        btn_delete.grid_remove()
        btn_export.grid_remove()
        btn_backup.grid_remove()
        btn_restore.grid_remove()
        btn_filter.grid_remove()
        btn_search.grid_remove()
        btn_sort.grid_remove()


def submit_report():
    name = entry_name.get().strip() or current_user.get('name')
    problem = combo_problem.get().strip()
    desc = text_desc.get("1.0", END).strip()
    location = entry_location.get().strip()

    if not (name and problem and desc and location):
        messagebox.showerror("Error", "All fields are required!")
        return

    citizen_id = current_user.get('id') if current_user.get('role') != 'Admin' else None

    try:
        conn = connect_db(DB_NAME)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO reports (citizen_id, citizen_name, problem_type, description, location, report_date) VALUES (%s,%s,%s,%s,%s,%s)",
            (citizen_id, name, problem, desc, location, datetime.now())
        )
        conn.commit()
        report_id = cursor.lastrowid
        conn.close()

        messagebox.showinfo("Success", "Report submitted successfully!")
        clear_form()
        # Send popup notification and optional email
        notify_message = f"Report submitted: {problem} - {location}"
        save_and_show_notification(citizen_id, report_id, notify_message)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to submit report: {e}")


def view_my_reports():
    username = entry_view_username.get().strip() or current_user.get('username')
    if not username:
        messagebox.showerror("Error", "Enter username")
        return
    try:
        conn = connect_db(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT r.id, r.citizen_id, r.citizen_name, r.problem_type, r.description, r.location, r.status, r.report_date FROM reports r JOIN citizens c ON r.citizen_id=c.id WHERE c.username=%s", (username,))
        rows = cursor.fetchall()
        conn.close()
        clear_tree()
        for row in rows:
            tree.insert('', END, values=format_row(row))
    except Exception as e:
        messagebox.showerror("Error", f"Failed to fetch reports: {e}")


def view_all_reports():
    try:
        conn = connect_db(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, citizen_id, citizen_name, problem_type, description, location, status, report_date FROM reports")
        rows = cursor.fetchall()
        conn.close()
        clear_tree()
        for row in rows:
            tree.insert('', END, values=format_row(row))
    except Exception as e:
        messagebox.showerror("Error", f"Failed to fetch reports: {e}")


def update_status():
    selected = tree.focus()
    if not selected:
        messagebox.showerror("Error", "Select a report!")
        return
    report_id = tree.item(selected)['values'][0]
    new_status = combo_status.get().strip()
    if not new_status:
        messagebox.showerror("Error", "Select a new status!")
        return
    try:
        conn = connect_db(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("UPDATE reports SET status=%s WHERE id=%s", (new_status, report_id))
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Status updated successfully!")
        # Notify citizen
        conn = connect_db(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT citizen_id FROM reports WHERE id=%s", (report_id,))
        citizen_row = cursor.fetchone()
        conn.close()
        citizen_id = citizen_row[0] if citizen_row else None
        save_and_show_notification(citizen_id, report_id, f"Your report #{report_id} status changed to {new_status}")
        view_all_reports()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to update status: {e}")


def delete_report():
    selected = tree.focus()
    if not selected:
        messagebox.showerror("Error", "Select a report to delete!")
        return
    report_id = tree.item(selected)['values'][0]
    try:
        conn = connect_db(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM reports WHERE id=%s", (report_id,))
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Report deleted successfully!")
        view_all_reports()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to delete: {e}")


def search_by_problem():
    problem = combo_search_problem.get().strip()
    if not problem:
        messagebox.showerror("Error", "Select a problem type!")
        return
    try:
        conn = connect_db(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, citizen_id, citizen_name, problem_type, description, location, status, report_date FROM reports WHERE problem_type=%s", (problem,))
        rows = cursor.fetchall()
        conn.close()
        clear_tree()
        for row in rows:
            tree.insert('', END, values=format_row(row))
    except Exception as e:
        messagebox.showerror("Error", f"Search failed: {e}")


def filter_by_status():
    status = combo_filter_status.get().strip()
    if not status:
        messagebox.showerror("Error", "Select a status!")
        return
    try:
        conn = connect_db(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, citizen_id, citizen_name, problem_type, description, location, status, report_date FROM reports WHERE status=%s", (status,))
        rows = cursor.fetchall()
        conn.close()
        clear_tree()
        for row in rows:
            tree.insert('', END, values=format_row(row))
    except Exception as e:
        messagebox.showerror("Error", f"Filter failed: {e}")


def sort_by_date():
    try:
        conn = connect_db(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, citizen_id, citizen_name, problem_type, description, location, status, report_date FROM reports ORDER BY report_date DESC")
        rows = cursor.fetchall()
        conn.close()
        clear_tree()
        for row in rows:
            tree.insert('', END, values=format_row(row))
    except Exception as e:
        messagebox.showerror("Error", f"Sort failed: {e}")


def export_to_csv():
    if not tree.get_children():
        messagebox.showerror("Error", "No reports to export!")
        return
    file_path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV files','*.csv')])
    if not file_path:
        return
    try:
        with open(file_path, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["ID","CitizenID","Name","Problem","Description","Location","Status","Date"])
            for row_id in tree.get_children():
                row = tree.item(row_id)['values']
                writer.writerow(row)
        messagebox.showinfo("Success", f"Reports exported to {file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Export failed: {e}")


def backup_data_csv():
    # Exports citizens and reports to CSV files in a chosen directory
    folder = filedialog.askdirectory()
    if not folder:
        return
    try:
        conn = connect_db(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, address, phone, nid, dob, username, password, role, email FROM citizens")
        citizens = cursor.fetchall()
        cursor.execute("SELECT id, citizen_id, citizen_name, problem_type, description, location, status, report_date FROM reports")
        reports = cursor.fetchall()
        conn.close()

        citizens_file = os.path.join(folder, 'citizens_backup.csv')
        reports_file = os.path.join(folder, 'reports_backup.csv')

        with open(citizens_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["id","name","address","phone","nid","dob","username","password","role","email"])
            for r in citizens:
                writer.writerow(r)

        with open(reports_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["id","citizen_id","citizen_name","problem_type","description","location","status","report_date"])
            for r in reports:
                # format date if needed
                r = list(r)
                if isinstance(r[7], datetime):
                    r[7] = r[7].strftime('%Y-%m-%d %H:%M:%S')
                writer.writerow(r)

        messagebox.showinfo("Success", f"Backup created in {folder}")
    except Exception as e:
        messagebox.showerror("Error", f"Backup failed: {e}")


def restore_data_csv():
    # User should select citizens_backup.csv and reports_backup.csv from a directory
    folder = filedialog.askdirectory()
    if not folder:
        return
    citizens_file = os.path.join(folder, 'citizens_backup.csv')
    reports_file = os.path.join(folder, 'reports_backup.csv')
    if not os.path.exists(citizens_file) or not os.path.exists(reports_file):
        messagebox.showerror("Error", "Backup files not found in selected folder")
        return

    try:
        conn = connect_db(DB_NAME)
        cursor = conn.cursor()
        # Clear existing tables (ask for confirmation)
        if not messagebox.askyesno("Confirm Restore", "This will DELETE existing data and restore from backup. Continue?"):
            return
        cursor.execute("DELETE FROM reports")
        cursor.execute("DELETE FROM citizens")
        conn.commit()

        # Restore citizens
        with open(citizens_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Preserve password field as stored (hashed)
                cursor.execute("INSERT INTO citizens (id, name, address, phone, nid, dob, username, password, role, email) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                               (row['id'], row['name'], row['address'], row['phone'], row['nid'], row['dob'] or None, row['username'], row['password'], row['role'], row.get('email')))
        conn.commit()

        # Restore reports
        with open(reports_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # parse date
                dt = None
                if row.get('report_date'):
                    try:
                        dt = datetime.strptime(row['report_date'], '%Y-%m-%d %H:%M:%S')
                    except Exception:
                        dt = None
                cursor.execute("INSERT INTO reports (id, citizen_id, citizen_name, problem_type, description, location, status, report_date) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                               (row['id'], row['citizen_id'] or None, row['citizen_name'], row['problem_type'], row['description'], row['location'], row['status'], dt))
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Data restored from backup")
    except Exception as e:
        messagebox.showerror("Error", f"Restore failed: {e}")


def save_and_show_notification(citizen_id, report_id, message_text):
    # Save to notifications table and show popup. Optionally send email if citizen has email
    try:
        conn = connect_db(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO notifications (citizen_id, report_id, message, sent_at) VALUES (%s,%s,%s,%s)",
                       (citizen_id, report_id, message_text, datetime.now()))
        conn.commit()
        conn.close()

        # popup
        messagebox.showinfo("Notification", message_text)

        # send email if available
        if citizen_id:
            conn = connect_db(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT email FROM citizens WHERE id=%s", (citizen_id,))
            row = cursor.fetchone()
            conn.close()
            if row and row[0]:
                send_email(row[0], "Citizen Portal Notification", message_text)
    except Exception as e:
        print("Notification save error:", e)


def clear_form():
    entry_name.delete(0, END)
    combo_problem.set("")
    text_desc.delete('1.0', END)
    entry_location.delete(0, END)


# --------------------- Bind Buttons ---------------------
btn_register.config(command=register_user)
btn_login.config(command=login_user)
btn_submit_report.config(command=submit_report)
btn_clear_form.config(command=clear_form)
btn_view_my.config(command=view_my_reports)
btn_view_all.config(command=view_all_reports)
btn_update_status.config(command=update_status)
btn_delete.config(command=delete_report)
btn_export.config(command=export_to_csv)
btn_filter.config(command=filter_by_status)
btn_search.config(command=search_by_problem)
btn_sort.config(command=sort_by_date)
btn_backup.config(command=backup_data_csv)
btn_restore.config(command=restore_data_csv)
btn_logout.config(command=lambda: (current_user.update({"id":None,"username":None,"role":None,"name":None}), switch_frame(login_frame)))

# --------------------- Pre-create an admin user if none exists ---------------------

def ensure_default_admin():
    try:
        conn = connect_db(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM citizens WHERE role='Admin'")
        count = cursor.fetchone()[0]
        if count == 0:
            default_admin_user = 'admin'
            default_admin_pass = 'admin123'  # advise changing on first run
            hashed = hash_password(default_admin_pass)
            cursor.execute("INSERT INTO citizens (name, username, password, role) VALUES (%s,%s,%s,%s)",
                           ('Administrator', default_admin_user, hashed.decode('utf-8'), 'Admin'))
            conn.commit()
        conn.close()
    except Exception as e:
        print('Admin ensure error:', e)

ensure_default_admin()

# Start at login frame
switch_frame(login_frame)

root.mainloop()
