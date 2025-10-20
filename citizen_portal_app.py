import os
import csv
from datetime import datetime
from tkinter import *
from tkinter import ttk, messagebox, filedialog
import threading

from database_config import create_database_and_tables, DB_NAME
from app_functions import (
    register_user_db, login_user_db, submit_report_db, fetch_reports_by_username,
    fetch_all_reports, update_report_status_db, delete_report_db,
    search_reports_by_problem_db, filter_reports_by_status_db, sort_reports_by_date_db,
    backup_data_csv_db, restore_data_csv_db, save_notification_db,
    get_email_by_citizen_id, send_email, hash_password, check_password, ensure_default_admin,
    get_notifications_db, mark_notification_read_db
)

# ---------------- Database Initialization ----------------
create_database_and_tables()
ensure_default_admin()

# ---------------- Tkinter Root ----------------
root = Tk()
root.title("Citizen Help Portal - Government Service")
root.geometry("1400x900")
root.configure(bg="#f5f5f5")

# Professional styling
STYLE = {
    "title_font": ("Arial", 18, "bold"),
    "header_font": ("Arial", 14, "bold"),
    "label_font": ("Arial", 11),
    "btn_font": ("Arial", 10, "bold"),
    "accent_color": "#2c3e50",
    "secondary_color": "#3498db",
    "success_color": "#27ae60",
    "warning_color": "#e67e22",
    "danger_color": "#e74c3c"
}

# ---------------- State ----------------
current_user = {"id": None, "username": None, "role": None, "name": None, "email": None}

# ---------------- Utility Functions ----------------
def clear_tree(tree):
    for item in tree.get_children():
        tree.delete(item)

def format_datetime(dt_string):
    try:
        if isinstance(dt_string, str):
            return datetime.strptime(dt_string, '%Y-%m-%d %H:%M:%S').strftime('%d/%m/%Y %H:%M')
        return dt_string.strftime('%d/%m/%Y %H:%M') if hasattr(dt_string, 'strftime') else str(dt_string)
    except:
        return str(dt_string)

def show_notification(message, type="info"):
    if type == "info":
        messagebox.showinfo("Notification", message)
    elif type == "warning":
        messagebox.showwarning("Warning", message)
    elif type == "error":
        messagebox.showerror("Error", message)
    elif type == "success":
        messagebox.showinfo("Success", message)

def refresh_notifications():
    if current_user["id"]:
        success, notifications = get_notifications_db(current_user["id"], unread_only=True)
        if success and notifications:
            notification_btn.config(text=f"Notifications ({len(notifications)})", bg=STYLE["warning_color"])
        else:
            notification_btn.config(text="Notifications", bg=STYLE["secondary_color"])

# ---------------- Frames ----------------
login_frame = Frame(root, bg=STYLE["accent_color"])
register_frame = Frame(root, bg="#f5f5f5")
citizen_frame = Frame(root, bg="#f5f5f5")
officer_frame = Frame(root, bg="#f5f5f5")
admin_frame = Frame(root, bg="#f5f5f5")

def switch_frame(frame):
    for f in (login_frame, register_frame, citizen_frame, officer_frame, admin_frame):
        f.pack_forget()
    frame.pack(fill='both', expand=True)
    refresh_notifications()

# ---------------- Login Frame ----------------
def login_click():
    username = entry_login_user.get().strip()
    password = entry_login_pass.get().strip()
    
    if not username or not password:
        show_notification("Please enter both username and password", "warning")
        return
    
    def do_login():
        success, result = login_user_db(username, password)
        root.after(0, lambda: handle_login_result(success, result))
    
    threading.Thread(target=do_login, daemon=True).start()

def handle_login_result(success, result):
    if success:
        current_user.update(result)
        show_notification(f"Welcome {result['name']}!", "success")
        
        if result['role'] == 'Citizen':
            refresh_citizen_reports()
            switch_frame(citizen_frame)
        elif result['role'] == 'Officer':
            refresh_officer_reports()
            switch_frame(officer_frame)
        elif result['role'] == 'Admin':
            refresh_admin_reports()
            switch_frame(admin_frame)
    else:
        show_notification(result, "error")

# Login UI
login_header = Frame(login_frame, bg=STYLE["accent_color"])
login_header.pack(fill='x', pady=(50, 30))
Label(login_header, text="Citizen Help Portal", font=("Arial", 24, "bold"), 
      fg="white", bg=STYLE["accent_color"]).pack(pady=10)
Label(login_header, text="Government Service Management System", font=("Arial", 14), 
      fg="#ecf0f1", bg=STYLE["accent_color"]).pack()

login_content = Frame(login_frame, bg="white", relief='raised', bd=1)
login_content.pack(pady=20, padx=100, fill='both', expand=True)

Label(login_content, text="User Login", font=STYLE["title_font"], bg="white").pack(pady=30)

login_inner = Frame(login_content, bg="white")
login_inner.pack(pady=20)

Label(login_inner, text="Username:", font=STYLE["label_font"], bg="white").grid(row=0, column=0, padx=10, pady=15, sticky=E)
entry_login_user = Entry(login_inner, width=25, font=STYLE["label_font"])
entry_login_user.grid(row=0, column=1, padx=10, pady=15)
entry_login_user.bind('<Return>', lambda e: login_click())

Label(login_inner, text="Password:", font=STYLE["label_font"], bg="white").grid(row=1, column=0, padx=10, pady=15, sticky=E)
entry_login_pass = Entry(login_inner, show='*', width=25, font=STYLE["label_font"])
entry_login_pass.grid(row=1, column=1, padx=10, pady=15)
entry_login_pass.bind('<Return>', lambda e: login_click())

btn_frame = Frame(login_inner, bg="white")
btn_frame.grid(row=2, column=0, columnspan=2, pady=30)

btn_login = Button(btn_frame, text="Login", width=15, font=STYLE["btn_font"], 
                   bg=STYLE["success_color"], fg="white", command=login_click)
btn_login.pack(pady=5)

btn_to_register = Button(btn_frame, text="Create New Account", width=15, font=STYLE["btn_font"],
                         bg=STYLE["secondary_color"], fg="white", command=lambda: switch_frame(register_frame))
btn_to_register.pack(pady=5)

# Default credentials label
Label(login_content, text="Default Admin: admin / admin123", font=("Arial", 9), 
      bg="white", fg="gray").pack(pady=10)

# ---------------- Register Frame ----------------
def register_click():
    data = {field: entries[field].get().strip() for field in fields}
    
    # Validation
    for field in ["Name", "Address", "Phone", "NID", "DOB (YYYY-MM-DD)", "Username", "Password"]:
        if not data[field]:
            show_notification(f"Please fill in {field}", "warning")
            return
    
    if data["Password"] != confirm_pass.get():
        show_notification("Passwords do not match!", "error")
        return
    
    def do_register():
        success, result = register_user_db(
            data["Name"], data["Address"], data["Phone"], data["NID"],
            data["DOB (YYYY-MM-DD)"], data["Email (optional)"], 
            data["Username"], data["Password"], data["Role"]
        )
        root.after(0, lambda: handle_register_result(success, result))
    
    threading.Thread(target=do_register, daemon=True).start()

def handle_register_result(success, result):
    if success:
        show_notification(result, "success")
        switch_frame(login_frame)
        # Clear form
        for field in fields:
            if field == "Role":
                entries[field].set("Citizen")
            else:
                entries[field].delete(0, END)
        confirm_pass.delete(0, END)
    else:
        show_notification(result, "error")

# Register UI
Label(register_frame, text="Register New Account", font=STYLE["title_font"], bg="#f5f5f5").pack(pady=30)

register_content = Frame(register_frame, bg="white", relief='raised', bd=1)
register_content.pack(pady=10, padx=50, fill='both', expand=True)

register_inner = Frame(register_content, bg="white")
register_inner.pack(pady=20, padx=20)

fields = ["Name", "Address", "Phone", "NID", "DOB (YYYY-MM-DD)", "Email (optional)", "Username", "Password", "Role"]
entries = {}

for idx, field in enumerate(fields):
    Label(register_inner, text=f"{field}:", font=STYLE["label_font"], bg="white").grid(
        row=idx, column=0, padx=10, pady=8, sticky=E)
    
    if field == "Role":
        entries[field] = StringVar(value="Citizen")
        combo = ttk.Combobox(register_inner, textvariable=entries[field], 
                            values=["Citizen", "Officer", "Admin"], state="readonly", width=22)
        combo.grid(row=idx, column=1, padx=10, pady=8)
    elif field == "Password":
        e = Entry(register_inner, show="*", width=25, font=STYLE["label_font"])
        e.grid(row=idx, column=1, padx=10, pady=8)
        entries[field] = e
    else:
        e = Entry(register_inner, width=25, font=STYLE["label_font"])
        e.grid(row=idx, column=1, padx=10, pady=8)
        entries[field] = e

# Confirm Password
Label(register_inner, text="Confirm Password:", font=STYLE["label_font"], bg="white").grid(
    row=len(fields), column=0, padx=10, pady=8, sticky=E)
confirm_pass = Entry(register_inner, show="*", width=25, font=STYLE["label_font"])
confirm_pass.grid(row=len(fields), column=1, padx=10, pady=8)

# Register buttons
btn_frame_register = Frame(register_inner, bg="white")
btn_frame_register.grid(row=len(fields)+1, column=0, columnspan=2, pady=20)

btn_register = Button(btn_frame_register, text="Create Account", width=20, font=STYLE["btn_font"],
                      bg=STYLE["success_color"], fg="white", command=register_click)
btn_register.pack(pady=10)

btn_back_login = Button(btn_frame_register, text="Back to Login", width=20, font=STYLE["btn_font"],
                        bg=STYLE["secondary_color"], fg="white", command=lambda: switch_frame(login_frame))
btn_back_login.pack(pady=5)

# ---------------- Citizen Dashboard ----------------
def refresh_citizen_reports():
    clear_tree(tree_citizen)
    success, reports = fetch_reports_by_username(current_user["id"])
    if success:
        for report in reports:
            tree_citizen.insert("", "end", values=(
                report['id'], report['problem_type'], report['description'][:50] + "..." if len(report['description']) > 50 else report['description'],
                report['location'], report['status'], report['priority'], format_datetime(report['created_at'])
            ))
    refresh_notifications()

def submit_report_citizen():
    problem_type = combo_problem_citizen.get().strip()
    description = text_desc_citizen.get("1.0", END).strip()
    location = entry_location_citizen.get().strip()
    priority = priority_var.get()
    
    if not all([problem_type, description, location]):
        show_notification("Please fill all required fields", "warning")
        return
    
    def do_submit():
        success, result = submit_report_db(current_user["id"], problem_type, description, location, priority)
        root.after(0, lambda: handle_submit_result(success, result))
    
    threading.Thread(target=do_submit, daemon=True).start()

def handle_submit_result(success, result):
    if success:
        show_notification(result, "success")
        text_desc_citizen.delete("1.0", END)
        entry_location_citizen.delete(0, END)
        combo_problem_citizen.set("")
        refresh_citizen_reports()
    else:
        show_notification(result, "error")

def show_notifications_dialog():
    success, notifications = get_notifications_db(current_user["id"])
    if not success:
        return
    
    notif_window = Toplevel(root)
    notif_window.title("Notifications")
    notif_window.geometry("500x400")
    notif_window.configure(bg="white")
    
    Label(notif_window, text="Your Notifications", font=STYLE["header_font"], bg="white").pack(pady=10)
    
    frame = Frame(notif_window, bg="white")
    frame.pack(fill='both', expand=True, padx=10, pady=10)
    
    scrollbar = Scrollbar(frame)
    scrollbar.pack(side=RIGHT, fill=Y)
    
    notif_list = Listbox(frame, yscrollcommand=scrollbar.set, font=("Arial", 10), bg="#fafafa")
    notif_list.pack(fill='both', expand=True)
    
    for notif in notifications:
        notif_list.insert(END, f"{format_datetime(notif['created_at'])}: {notif['message']}")
        if not notif['is_read']:
            mark_notification_read_db(notif['id'])
    
    scrollbar.config(command=notif_list.yview)
    refresh_notifications()

# Citizen Header
citizen_header = Frame(citizen_frame, bg=STYLE["accent_color"])
citizen_header.pack(fill='x')
Label(citizen_header, text=f"Citizen Dashboard - Welcome {current_user.get('name', 'User')}", 
      font=STYLE["title_font"], fg="white", bg=STYLE["accent_color"]).pack(pady=15)

# Notification button
notification_btn = Button(citizen_header, text="Notifications", font=STYLE["btn_font"],
                         bg=STYLE["secondary_color"], fg="white", command=show_notifications_dialog)
notification_btn.pack(side=RIGHT, padx=20, pady=10)

# Citizen Tabs
tab_citizen = ttk.Notebook(citizen_frame)
tab_submit = Frame(tab_citizen, bg="#f5f5f5")
tab_view = Frame(tab_citizen, bg="#f5f5f5")
tab_citizen.add(tab_submit, text="Submit New Report")
tab_citizen.add(tab_view, text="My Reports")
tab_citizen.pack(fill='both', expand=True, padx=10, pady=10)

# Submit Tab
Label(tab_submit, text="Submit New Service Request", font=STYLE["header_font"], bg="#f5f5f5").pack(pady=20)

submit_content = Frame(tab_submit, bg="white", relief='raised', bd=1)
submit_content.pack(pady=10, padx=50, fill='both', expand=True)

submit_inner = Frame(submit_content, bg="white")
submit_inner.pack(pady=20, padx=20)

Label(submit_inner, text="Problem Type:*", font=STYLE["label_font"], bg="white").grid(row=0, column=0, padx=10, pady=15, sticky=E)
combo_problem_citizen = ttk.Combobox(submit_inner, values=[
    "Health Emergency", "Corruption Report", "Extortion Complaint", 
    "Infrastructure Issue", "Utility Problem", "Public Safety", "Other"
], width=27, state="readonly")
combo_problem_citizen.grid(row=0, column=1, padx=10, pady=15)

Label(submit_inner, text="Priority:*", font=STYLE["label_font"], bg="white").grid(row=1, column=0, padx=10, pady=15, sticky=E)
priority_var = StringVar(value="Medium")
priority_frame = Frame(submit_inner, bg="white")
priority_frame.grid(row=1, column=1, padx=10, pady=15, sticky=W)
Radiobutton(priority_frame, text="Low", variable=priority_var, value="Low", bg="white").pack(side=LEFT)
Radiobutton(priority_frame, text="Medium", variable=priority_var, value="Medium", bg="white").pack(side=LEFT)
Radiobutton(priority_frame, text="High", variable=priority_var, value="High", bg="white").pack(side=LEFT)
Radiobutton(priority_frame, text="Critical", variable=priority_var, value="Critical", bg="white").pack(side=LEFT)

Label(submit_inner, text="Location:*", font=STYLE["label_font"], bg="white").grid(row=2, column=0, padx=10, pady=15, sticky=E)
entry_location_citizen = Entry(submit_inner, width=30, font=STYLE["label_font"])
entry_location_citizen.grid(row=2, column=1, padx=10, pady=15)

Label(submit_inner, text="Description:*", font=STYLE["label_font"], bg="white").grid(row=3, column=0, padx=10, pady=15, sticky=NE)
text_desc_citizen = Text(submit_inner, width=50, height=8, font=("Arial", 10))
text_desc_citizen.grid(row=3, column=1, padx=10, pady=15)

btn_submit_report_citizen = Button(submit_inner, text="Submit Report", width=20, font=STYLE["btn_font"],
                                  bg=STYLE["success_color"], fg="white", command=submit_report_citizen)
btn_submit_report_citizen.grid(row=4, column=0, columnspan=2, pady=20)

# View Tab
view_header = Frame(tab_view, bg="#f5f5f5")
view_header.pack(fill='x', pady=10)
Label(view_header, text="My Submitted Reports", font=STYLE["header_font"], bg="#f5f5f5").pack(side=LEFT, padx=20)
Button(view_header, text="Refresh", font=STYLE["btn_font"], bg=STYLE["secondary_color"], fg="white",
       command=refresh_citizen_reports).pack(side=RIGHT, padx=20)

# Treeview with scrollbar
tree_frame = Frame(tab_view, bg="#f5f5f5")
tree_frame.pack(fill='both', expand=True, padx=10, pady=10)

tree_citizen = ttk.Treeview(tree_frame, columns=("ID", "Problem", "Description", "Location", "Status", "Priority", "Date"), show='headings', height=15)
columns = {
    "ID": 80, "Problem": 120, "Description": 200, "Location": 120, 
    "Status": 100, "Priority": 80, "Date": 120
}
for col, width in columns.items():
    tree_citizen.heading(col, text=col)
    tree_citizen.column(col, width=width, anchor='center')

scrollbar_citizen = Scrollbar(tree_frame, orient=VERTICAL, command=tree_citizen.yview)
tree_citizen.configure(yscrollcommand=scrollbar_citizen.set)

tree_citizen.pack(side=LEFT, fill='both', expand=True)
scrollbar_citizen.pack(side=RIGHT, fill=Y)

# ---------------- Officer Dashboard ----------------
def refresh_officer_reports():
    clear_tree(tree_officer)
    success, reports = fetch_all_reports()
    if success:
        for report in reports:
            tree_officer.insert("", "end", values=(
                report['id'], report['problem_type'], report['description'][:50] + "..." if len(report['description']) > 50 else report['description'],
                report['location'], report['status'], report['priority'], report['citizen_name'], format_datetime(report['created_at'])
            ))
    refresh_notifications()

def update_report_status():
    selected = tree_officer.selection()
    if not selected:
        show_notification("Please select a report to update", "warning")
        return
    
    report_id = tree_officer.item(selected[0])['values'][0]
    new_status = status_var_officer.get()
    notes = text_notes_officer.get("1.0", END).strip()
    
    def do_update():
        success, result = update_report_status_db(report_id, new_status, notes, current_user["id"])
        root.after(0, lambda: handle_update_result(success, result))
    
    threading.Thread(target=do_update, daemon=True).start()

def handle_update_result(success, result):
    if success:
        show_notification(result, "success")
        text_notes_officer.delete("1.0", END)
        refresh_officer_reports()
    else:
        show_notification(result, "error")

# Officer Header
officer_header = Frame(officer_frame, bg=STYLE["accent_color"])
officer_header.pack(fill='x')
Label(officer_header, text=f"Officer Dashboard - Welcome {current_user.get('name', 'User')}", 
      font=STYLE["title_font"], fg="white", bg=STYLE["accent_color"]).pack(pady=15)

notification_btn_officer = Button(officer_header, text="Notifications", font=STYLE["btn_font"],
                                 bg=STYLE["secondary_color"], fg="white", command=show_notifications_dialog)
notification_btn_officer.pack(side=RIGHT, padx=20, pady=10)

# Officer Tabs
tab_officer = ttk.Notebook(officer_frame)
tab_officer_view = Frame(tab_officer, bg="#f5f5f5")
tab_officer_manage = Frame(tab_officer, bg="#f5f5f5")
tab_officer.add(tab_officer_view, text="View All Reports")
tab_officer.add(tab_officer_manage, text="Update Status")
tab_officer.pack(fill='both', expand=True, padx=10, pady=10)

# View Tab
Label(tab_officer_view, text="All Citizen Reports", font=STYLE["header_font"], bg="#f5f5f5").pack(pady=10)

tree_frame_officer = Frame(tab_officer_view, bg="#f5f5f5")
tree_frame_officer.pack(fill='both', expand=True, padx=10, pady=10)

tree_officer = ttk.Treeview(tree_frame_officer, columns=("ID", "Problem", "Description", "Location", "Status", "Priority", "Citizen", "Date"), show='headings', height=15)
columns_officer = {
    "ID": 80, "Problem": 120, "Description": 180, "Location": 100, 
    "Status": 100, "Priority": 80, "Citizen": 120, "Date": 120
}
for col, width in columns_officer.items():
    tree_officer.heading(col, text=col)
    tree_officer.column(col, width=width, anchor='center')

scrollbar_officer = Scrollbar(tree_frame_officer, orient=VERTICAL, command=tree_officer.yview)
tree_officer.configure(yscrollcommand=scrollbar_officer.set)

tree_officer.pack(side=LEFT, fill='both', expand=True)
scrollbar_officer.pack(side=RIGHT, fill=Y)

Button(tab_officer_view, text="Refresh Reports", font=STYLE["btn_font"], bg=STYLE["secondary_color"], fg="white",
       command=refresh_officer_reports).pack(pady=10)

# Manage Tab
Label(tab_officer_manage, text="Update Report Status", font=STYLE["header_font"], bg="#f5f5f5").pack(pady=20)

manage_content = Frame(tab_officer_manage, bg="white", relief='raised', bd=1)
manage_content.pack(pady=10, padx=50, fill='both', expand=True)

manage_inner = Frame(manage_content, bg="white")
manage_inner.pack(pady=20, padx=20)

Label(manage_inner, text="Select Report from View Tab", font=STYLE["label_font"], bg="white").grid(row=0, column=0, columnspan=2, pady=10)

Label(manage_inner, text="New Status:", font=STYLE["label_font"], bg="white").grid(row=1, column=0, padx=10, pady=15, sticky=E)
status_var_officer = StringVar(value="In Progress")
status_combo_officer = ttk.Combobox(manage_inner, textvariable=status_var_officer, 
                                   values=["Pending", "In Progress", "Resolved", "Rejected"], 
                                   state="readonly", width=27)
status_combo_officer.grid(row=1, column=1, padx=10, pady=15)

Label(manage_inner, text="Officer Notes:", font=STYLE["label_font"], bg="white").grid(row=2, column=0, padx=10, pady=15, sticky=NE)
text_notes_officer = Text(manage_inner, width=50, height=6, font=("Arial", 10))
text_notes_officer.grid(row=2, column=1, padx=10, pady=15)

btn_update_status = Button(manage_inner, text="Update Status", width=20, font=STYLE["btn_font"],
                          bg=STYLE["success_color"], fg="white", command=update_report_status)
btn_update_status.grid(row=3, column=0, columnspan=2, pady=20)

# ---------------- Admin Dashboard ----------------
def refresh_admin_reports():
    clear_tree(tree_admin)
    success, reports = fetch_all_reports()
    if success:
        for report in reports:
            tree_admin.insert("", "end", values=(
                report['id'], report['problem_type'], report['description'][:50] + "..." if len(report['description']) > 50 else report['description'],
                report['location'], report['status'], report['priority'], report['citizen_name'], format_datetime(report['created_at'])
            ))
    refresh_notifications()

def search_reports_admin():
    search_term = entry_search_admin.get().strip()
    if not search_term:
        refresh_admin_reports()
        return
    
    clear_tree(tree_admin)
    success, reports = search_reports_by_problem_db(search_term)
    if success:
        for report in reports:
            tree_admin.insert("", "end", values=(
                report['id'], report['problem_type'], report['description'][:50] + "..." if len(report['description']) > 50 else report['description'],
                report['location'], report['status'], report['priority'], report['citizen_name'], format_datetime(report['created_at'])
            ))

def filter_reports_admin():
    status = filter_var_admin.get()
    if status == "All":
        refresh_admin_reports()
        return
    
    clear_tree(tree_admin)
    success, reports = filter_reports_by_status_db(status)
    if success:
        for report in reports:
            tree_admin.insert("", "end", values=(
                report['id'], report['problem_type'], report['description'][:50] + "..." if len(report['description']) > 50 else report['description'],
                report['location'], report['status'], report['priority'], report['citizen_name'], format_datetime(report['created_at'])
            ))

def delete_report_admin():
    selected = tree_admin.selection()
    if not selected:
        show_notification("Please select a report to delete", "warning")
        return
    
    report_id = tree_admin.item(selected[0])['values'][0]
    
    if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete report #{report_id}?"):
        success, result = delete_report_db(report_id)
        if success:
            show_notification(result, "success")
            refresh_admin_reports()
        else:
            show_notification(result, "error")

def backup_data_admin():
    def do_backup():
        success, result = backup_data_csv_db()
        root.after(0, lambda: show_notification(result, "success" if success else "error"))
    
    threading.Thread(target=do_backup, daemon=True).start()

def restore_data_admin():
    users_file = filedialog.askopenfilename(title="Select Users Backup CSV", filetypes=[("CSV files", "*.csv")])
    reports_file = filedialog.askopenfilename(title="Select Reports Backup CSV", filetypes=[("CSV files", "*.csv")])
    
    if users_file and reports_file:
        success, result = restore_data_csv_db(users_file, reports_file)
        show_notification(result, "success" if success else "error")
        if success:
            refresh_admin_reports()

# Admin Header
admin_header = Frame(admin_frame, bg=STYLE["accent_color"])
admin_header.pack(fill='x')
Label(admin_header, text=f"Admin Dashboard - Welcome {current_user.get('name', 'User')}", 
      font=STYLE["title_font"], fg="white", bg=STYLE["accent_color"]).pack(pady=15)

notification_btn_admin = Button(admin_header, text="Notifications", font=STYLE["btn_font"],
                               bg=STYLE["secondary_color"], fg="white", command=show_notifications_dialog)
notification_btn_admin.pack(side=RIGHT, padx=20, pady=10)

# Admin Tabs
tab_admin = ttk.Notebook(admin_frame)
tab_admin_view = Frame(tab_admin, bg="#f5f5f5")
tab_admin_manage = Frame(tab_admin, bg="#f5f5f5")
tab_admin.add(tab_admin_view, text="All Reports")
tab_admin.add(tab_admin_manage, text="Manage Data")
tab_admin.pack(fill='both', expand=True, padx=10, pady=10)

# View Tab
view_header_admin = Frame(tab_admin_view, bg="#f5f5f5")
view_header_admin.pack(fill='x', pady=10)

Label(view_header_admin, text="All System Reports", font=STYLE["header_font"], bg="#f5f5f5").pack(side=LEFT, padx=20)

# Search and Filter
search_frame = Frame(view_header_admin, bg="#f5f5f5")
search_frame.pack(side=RIGHT, padx=20)

Label(search_frame, text="Search:", font=STYLE["label_font"], bg="#f5f5f5").pack(side=LEFT)
entry_search_admin = Entry(search_frame, width=15, font=STYLE["label_font"])
entry_search_admin.pack(side=LEFT, padx=5)
entry_search_admin.bind('<Return>', lambda e: search_reports_admin())

Button(search_frame, text="Search", font=STYLE["btn_font"], bg=STYLE["secondary_color"], fg="white",
       command=search_reports_admin).pack(side=LEFT, padx=5)

Label(search_frame, text="Filter:", font=STYLE["label_font"], bg="#f5f5f5").pack(side=LEFT, padx=(20,5))
filter_var_admin = StringVar(value="All")
filter_combo_admin = ttk.Combobox(search_frame, textvariable=filter_var_admin, 
                                 values=["All", "Pending", "In Progress", "Resolved", "Rejected"], 
                                 state="readonly", width=12)
filter_combo_admin.pack(side=LEFT, padx=5)
filter_combo_admin.bind('<<ComboboxSelected>>', lambda e: filter_reports_admin())

# Admin Treeview
tree_frame_admin = Frame(tab_admin_view, bg="#f5f5f5")
tree_frame_admin.pack(fill='both', expand=True, padx=10, pady=10)

tree_admin = ttk.Treeview(tree_frame_admin, columns=("ID", "Problem", "Description", "Location", "Status", "Priority", "Citizen", "Date"), show='headings', height=15)
for col, width in columns_officer.items():
    tree_admin.heading(col, text=col)
    tree_admin.column(col, width=width, anchor='center')

scrollbar_admin = Scrollbar(tree_frame_admin, orient=VERTICAL, command=tree_admin.yview)
tree_admin.configure(yscrollcommand=scrollbar_admin.set)

tree_admin.pack(side=LEFT, fill='both', expand=True)
scrollbar_admin.pack(side=RIGHT, fill=Y)

# Admin actions
action_frame_admin = Frame(tab_admin_view, bg="#f5f5f5")
action_frame_admin.pack(fill='x', pady=10)

Button(action_frame_admin, text="Refresh", font=STYLE["btn_font"], bg=STYLE["secondary_color"], fg="white",
       command=refresh_admin_reports).pack(side=LEFT, padx=20)
Button(action_frame_admin, text="Delete Selected", font=STYLE["btn_font"], bg=STYLE["danger_color"], fg="white",
       command=delete_report_admin).pack(side=LEFT, padx=20)

# Manage Tab
Label(tab_admin_manage, text="Data Management", font=STYLE["header_font"], bg="#f5f5f5").pack(pady=20)

manage_admin_content = Frame(tab_admin_manage, bg="white", relief='raised', bd=1)
manage_admin_content.pack(pady=10, padx=50, fill='both', expand=True)

manage_admin_inner = Frame(manage_admin_content, bg="white")
manage_admin_inner.pack(pady=30, padx=20)

# Backup/Restore section
Label(manage_admin_inner, text="Data Backup & Restore", font=STYLE["header_font"], bg="white").grid(row=0, column=0, columnspan=2, pady=20)

Button(manage_admin_inner, text="Backup Data to CSV", width=20, font=STYLE["btn_font"],
       bg=STYLE["success_color"], fg="white", command=backup_data_admin).grid(row=1, column=0, padx=20, pady=15)

Button(manage_admin_inner, text="Restore Data from CSV", width=20, font=STYLE["btn_font"],
       bg=STYLE["warning_color"], fg="white", command=restore_data_admin).grid(row=1, column=1, padx=20, pady=15)

Label(manage_admin_inner, text="System Statistics", font=STYLE["header_font"], bg="white").grid(row=2, column=0, columnspan=2, pady=20)

# Statistics would go here
stats_frame = Frame(manage_admin_inner, bg="white")
stats_frame.grid(row=3, column=0, columnspan=2, pady=10)

# ---------------- Logout Buttons ----------------
def logout():
    current_user.update({"id": None, "username": None, "role": None, "name": None, "email": None})
    switch_frame(login_frame)
    entry_login_user.delete(0, END)
    entry_login_pass.delete(0, END)

for frame, btn_name in [(citizen_frame, "btn_logout_citizen"), (officer_frame, "btn_logout_officer"), (admin_frame, "btn_logout_admin")]:
    btn = Button(frame, text="Logout", width=15, font=STYLE["btn_font"], 
                bg=STYLE["danger_color"], fg="white", command=logout)
    btn.pack(pady=10)

# ---------------- Start Application ----------------
switch_frame(login_frame)
root.mainloop()