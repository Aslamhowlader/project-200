import sqlite3
import hashlib
import csv
import os
from datetime import datetime
from database_config import get_db_connection, DB_NAME

# Password hashing functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_password(hashed_password, user_password):
    return hashed_password == hashlib.sha256(user_password.encode()).hexdigest()

# User management functions
def register_user_db(name, address, phone, nid, dob, email, username, password, role):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        hashed_pwd = hash_password(password)
        
        cursor.execute('''
            INSERT INTO users (name, address, phone, nid, dob, email, username, password, role)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (name, address, phone, nid, dob, email, username, hashed_pwd, role))
        
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        # Create welcome notification
        save_notification_db(user_id, f"Welcome to Citizen Help Portal! Your account has been created as {role}.")
        
        return True, "Registration successful!"
    except sqlite3.IntegrityError as e:
        return False, "Username or NID already exists!"
    except Exception as e:
        return False, f"Registration failed: {str(e)}"

def login_user_db(username, password):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, username, password, role, name, email FROM users WHERE username = ?
        ''', (username,))
        
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password(user['password'], password):
            return True, {
                'id': user['id'],
                'username': user['username'],
                'role': user['role'],
                'name': user['name'],
                'email': user['email']
            }
        else:
            return False, "Invalid username or password!"
    except Exception as e:
        return False, f"Login failed: {str(e)}"

def ensure_default_admin():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if admin exists
        cursor.execute("SELECT id FROM users WHERE role = 'Admin'")
        admin = cursor.fetchone()
        
        if not admin:
            hashed_pwd = hash_password("admin123")
            cursor.execute('''
                INSERT INTO users (name, address, phone, nid, dob, email, username, password, role)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', ("System Administrator", "Central Office", "0000000000", "0000000000", 
                  "2000-01-01", "admin@portal.gov", "admin", hashed_pwd, "Admin"))
            
            conn.commit()
        conn.close()
    except Exception as e:
        print(f"Admin setup error: {e}")

# Report management functions
def submit_report_db(citizen_id, problem_type, description, location, priority="Medium"):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO reports (citizen_id, problem_type, description, location, priority)
            VALUES (?, ?, ?, ?, ?)
        ''', (citizen_id, problem_type, description, location, priority))
        
        report_id = cursor.lastrowid
        
        # Create notification for citizen
        save_notification_db(citizen_id, f"Your report #{report_id} has been submitted successfully.")
        
        # Notify officers about new report
        cursor.execute("SELECT id FROM users WHERE role = 'Officer'")
        officers = cursor.fetchall()
        for officer in officers:
            save_notification_db(officer['id'], f"New report #{report_id} submitted: {problem_type}")
        
        conn.commit()
        conn.close()
        return True, "Report submitted successfully!"
    except Exception as e:
        return False, f"Failed to submit report: {str(e)}"

def fetch_reports_by_username(citizen_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT r.id, r.problem_type, r.description, r.location, r.status, 
                   r.priority, r.created_at, r.updated_at, r.officer_notes,
                   u.name as citizen_name
            FROM reports r
            JOIN users u ON r.citizen_id = u.id
            WHERE r.citizen_id = ?
            ORDER BY r.created_at DESC
        ''', (citizen_id,))
        
        reports = cursor.fetchall()
        conn.close()
        return True, [dict(report) for report in reports]
    except Exception as e:
        return False, f"Failed to fetch reports: {str(e)}"

def fetch_all_reports():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT r.id, r.problem_type, r.description, r.location, r.status, 
                   r.priority, r.created_at, r.updated_at, r.officer_notes,
                   u.name as citizen_name, u.phone as citizen_phone
            FROM reports r
            JOIN users u ON r.citizen_id = u.id
            ORDER BY r.created_at DESC
        ''')
        
        reports = cursor.fetchall()
        conn.close()
        return True, [dict(report) for report in reports]
    except Exception as e:
        return False, f"Failed to fetch reports: {str(e)}"

def update_report_status_db(report_id, status, officer_notes=None, officer_id=None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE reports 
            SET status = ?, officer_notes = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (status, officer_notes, report_id))
        
        # Get citizen_id for notification
        cursor.execute('SELECT citizen_id FROM reports WHERE id = ?', (report_id,))
        report = cursor.fetchone()
        
        if report:
            save_notification_db(report['citizen_id'], 
                               f"Your report #{report_id} status updated to: {status}")
        
        conn.commit()
        conn.close()
        return True, "Report status updated successfully!"
    except Exception as e:
        return False, f"Failed to update report: {str(e)}"

def delete_report_db(report_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM reports WHERE id = ?', (report_id,))
        conn.commit()
        conn.close()
        return True, "Report deleted successfully!"
    except Exception as e:
        return False, f"Failed to delete report: {str(e)}"

# Search and filter functions
def search_reports_by_problem_db(search_term):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT r.id, r.problem_type, r.description, r.location, r.status, 
                   r.priority, r.created_at, r.updated_at, r.officer_notes,
                   u.name as citizen_name
            FROM reports r
            JOIN users u ON r.citizen_id = u.id
            WHERE r.problem_type LIKE ? OR r.description LIKE ? OR u.name LIKE ?
            ORDER BY r.created_at DESC
        ''', (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%'))
        
        reports = cursor.fetchall()
        conn.close()
        return True, [dict(report) for report in reports]
    except Exception as e:
        return False, f"Search failed: {str(e)}"

def filter_reports_by_status_db(status):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT r.id, r.problem_type, r.description, r.location, r.status, 
                   r.priority, r.created_at, r.updated_at, r.officer_notes,
                   u.name as citizen_name
            FROM reports r
            JOIN users u ON r.citizen_id = u.id
            WHERE r.status = ?
            ORDER BY r.created_at DESC
        ''', (status,))
        
        reports = cursor.fetchall()
        conn.close()
        return True, [dict(report) for report in reports]
    except Exception as e:
        return False, f"Filter failed: {str(e)}"

def sort_reports_by_date_db(order='DESC'):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        order_clause = "DESC" if order.upper() == "DESC" else "ASC"
        cursor.execute(f'''
            SELECT r.id, r.problem_type, r.description, r.location, r.status, 
                   r.priority, r.created_at, r.updated_at, r.officer_notes,
                   u.name as citizen_name
            FROM reports r
            JOIN users u ON r.citizen_id = u.id
            ORDER BY r.created_at {order_clause}
        ''')
        
        reports = cursor.fetchall()
        conn.close()
        return True, [dict(report) for report in reports]
    except Exception as e:
        return False, f"Sort failed: {str(e)}"

# Backup and restore functions
def backup_data_csv_db():
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = "backups"
        os.makedirs(backup_dir, exist_ok=True)
        
        conn = get_db_connection()
        
        # Backup users
        users_file = os.path.join(backup_dir, f"users_backup_{timestamp}.csv")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        
        with open(users_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([i[0] for i in cursor.description])
            writer.writerows(users)
        
        # Backup reports
        reports_file = os.path.join(backup_dir, f"reports_backup_{timestamp}.csv")
        cursor.execute("SELECT * FROM reports")
        reports = cursor.fetchall()
        
        with open(reports_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([i[0] for i in cursor.description])
            writer.writerows(reports)
        
        conn.close()
        return True, f"Backup created successfully: {users_file}, {reports_file}"
    except Exception as e:
        return False, f"Backup failed: {str(e)}"

def restore_data_csv_db(users_file, reports_file):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Restore users
        if users_file and os.path.exists(users_file):
            cursor.execute("DELETE FROM users")
            with open(users_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cursor.execute('''
                        INSERT INTO users (id, name, address, phone, nid, dob, email, username, password, role, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (row['id'], row['name'], row['address'], row['phone'], row['nid'], 
                          row['dob'], row['email'], row['username'], row['password'], 
                          row['role'], row['created_at']))
        
        # Restore reports
        if reports_file and os.path.exists(reports_file):
            cursor.execute("DELETE FROM reports")
            with open(reports_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cursor.execute('''
                        INSERT INTO reports (id, citizen_id, problem_type, description, location, status, priority, created_at, updated_at, officer_notes)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (row['id'], row['citizen_id'], row['problem_type'], row['description'],
                          row['location'], row['status'], row['priority'], row['created_at'],
                          row['updated_at'], row['officer_notes']))
        
        conn.commit()
        conn.close()
        return True, "Data restored successfully!"
    except Exception as e:
        return False, f"Restore failed: {str(e)}"

# Notification functions
def save_notification_db(user_id, message):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO notifications (user_id, message)
            VALUES (?, ?)
        ''', (user_id, message))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Notification save failed: {e}")
        return False

def get_notifications_db(user_id, unread_only=False):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if unread_only:
            cursor.execute('''
                SELECT id, message, created_at FROM notifications 
                WHERE user_id = ? AND is_read = 0 
                ORDER BY created_at DESC
            ''', (user_id,))
        else:
            cursor.execute('''
                SELECT id, message, created_at, is_read FROM notifications 
                WHERE user_id = ? 
                ORDER BY created_at DESC
            ''', (user_id,))
        
        notifications = cursor.fetchall()
        conn.close()
        return True, [dict(notif) for notif in notifications]
    except Exception as e:
        return False, f"Failed to fetch notifications: {str(e)}"

def mark_notification_read_db(notification_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE notifications SET is_read = 1 WHERE id = ?
        ''', (notification_id,))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        return False

def get_email_by_citizen_id(citizen_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT email FROM users WHERE id = ?', (citizen_id,))
        user = cursor.fetchone()
        conn.close()
        
        return user['email'] if user else None
    except Exception as e:
        return None

# Email function (placeholder - would integrate with actual email service)
def send_email(to_email, subject, message):
    # This is a placeholder for actual email integration
    print(f"Email to {to_email}: {subject} - {message}")
    return True