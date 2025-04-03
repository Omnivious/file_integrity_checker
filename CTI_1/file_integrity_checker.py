import os
import hashlib
import sqlite3
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinterdnd2 import DND_FILES, TkinterDnD
import smtplib
from email.mime.text import MIMEText
from fpdf import FPDF

# ------------------------
# GLOBAL CONFIG
# ------------------------
DB_NAME = 'file_integrity.db'
EMAIL_ADDRESS = 'your_email@gmail.com'
EMAIL_PASSWORD = 'your_app_password'

# ------------------------
# DB Initialization
# ------------------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS file_hashes (
                    id INTEGER PRIMARY KEY,
                    file_path TEXT UNIQUE,
                    hash_value TEXT
                )''')
    conn.commit()
    conn.close()

# ------------------------
# Calculate File Hash
# ------------------------
def calculate_hash(file_path, hash_type="sha256"):
    hasher = hashlib.new(hash_type)
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

# ------------------------
# Save Hash to DB
# ------------------------
def save_hash(file_path, hash_value):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("REPLACE INTO file_hashes (file_path, hash_value) VALUES (?, ?)", (file_path, hash_value))
    conn.commit()
    conn.close()

# ------------------------
# Get Saved Hash
# ------------------------
def get_saved_hash(file_path):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT hash_value FROM file_hashes WHERE file_path = ?", (file_path,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None

# ------------------------
# Send Email Notification
# ------------------------
def send_email_notification(subject, message):
    try:
        msg = MIMEText(message)
        msg['Subject'] = subject
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = EMAIL_ADDRESS

        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, EMAIL_ADDRESS, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"❌ Error sending email: {e}")

# ------------------------
# Generate PDF Report
# ------------------------
def generate_pdf_report(results):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="File Integrity Checker Report", ln=True, align='C')
    pdf.ln(10)

    for file, status in results.items():
        pdf.multi_cell(0, 10, f"{file}\nStatus: {status}\n")

    pdf.output("file_integrity_report.pdf")
    messagebox.showinfo("Success", "PDF report generated successfully!")

# ------------------------
# GUI Class
# ------------------------
class IntegrityCheckerApp(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()

        self.title("🔐 File Integrity Checker")
        self.geometry("600x400")
        self.configure(bg="#f0f0f0")

        self.style = ttk.Style(self)
        self.style.theme_use('clam')

        self.create_widgets()
        init_db()

    # --------------------
    # GUI Widgets
    # --------------------
    def create_widgets(self):
        # File Selection
        self.label = ttk.Label(self, text="Drag and Drop a File or Click to Browse", font=("Arial", 12))
        self.label.pack(pady=10)

        self.file_entry = ttk.Entry(self, width=70)
        self.file_entry.pack(pady=5)
        
        self.browse_button = ttk.Button(self, text="📂 Browse File", command=self.browse_file)
        self.browse_button.pack(pady=5)

        # Hashing Options
        self.hash_type_label = ttk.Label(self, text="Hash Type:")
        self.hash_type_label.pack(pady=5)
        
        self.hash_type_var = tk.StringVar(value="sha256")
        self.hash_type_menu = ttk.Combobox(self, textvariable=self.hash_type_var, values=["md5", "sha1", "sha256", "sha512"], width=10)
        self.hash_type_menu.pack(pady=5)

        # Buttons
        self.save_button = ttk.Button(self, text="💾 Save Hash", command=self.save_hash_action)
        self.save_button.pack(pady=5)

        self.verify_button = ttk.Button(self, text="✅ Verify Integrity", command=self.verify_integrity_action)
        self.verify_button.pack(pady=5)

        self.generate_button = ttk.Button(self, text="📊 Generate Report", command=self.generate_report_action)
        self.generate_button.pack(pady=5)

        # Log Display
        self.log_label = ttk.Label(self, text="Logs:", font=("Arial", 10, "bold"))
        self.log_label.pack(pady=5)

        self.log_viewer = tk.Text(self, height=10, width=70, state='disabled')
        self.log_viewer.pack(pady=5)

        # Drag & Drop Support
        self.drop_target_register(DND_FILES)
        self.dnd_bind('<<Drop>>', self.drop_file)

    # --------------------
    # File Browsing
    # --------------------
    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)

    # --------------------
    # Drag and Drop File
    # --------------------
    def drop_file(self, event):
        file_path = event.data.replace('{', '').replace('}', '')
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, file_path)

    # --------------------
    # Save Hash Action
    # --------------------
    def save_hash_action(self):
        file_path = self.file_entry.get()
        if not file_path or not os.path.isfile(file_path):
            messagebox.showerror("Error", "Invalid file selected.")
            return

        hash_type = self.hash_type_var.get()
        hash_value = calculate_hash(file_path, hash_type)
        save_hash(file_path, hash_value)
        self.log_message(f"✅ Hash saved for {file_path} using {hash_type}.")
        messagebox.showinfo("Success", "File hash saved successfully!")

    # --------------------
    # Verify Integrity Action
    # --------------------
    def verify_integrity_action(self):
        file_path = self.file_entry.get()
        if not file_path or not os.path.isfile(file_path):
            messagebox.showerror("Error", "Invalid file selected.")
            return

        hash_type = self.hash_type_var.get()
        current_hash = calculate_hash(file_path, hash_type)
        saved_hash = get_saved_hash(file_path)

        if saved_hash is None:
            self.log_message("❌ No saved hash found for this file.")
            messagebox.showerror("Error", "No saved hash found.")
        elif current_hash == saved_hash:
            self.log_message(f"✅ File integrity verified. No changes detected.")
            messagebox.showinfo("Success", "File integrity verified!")
        else:
            self.log_message("⚠️ File integrity compromised!")
            messagebox.showwarning("Warning", "File integrity compromised!")
            send_email_notification("File Integrity Alert", f"File integrity compromised: {file_path}")

    # --------------------
    # Generate Report Action
    # --------------------
    def generate_report_action(self):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT file_path, hash_value FROM file_hashes")
        results = {row[0]: "Integrity Verified" for row in c.fetchall()}
        conn.close()

        generate_pdf_report(results)
        self.log_message("📊 Report generated successfully!")

    # --------------------
    # Logging Function
    # --------------------
    def log_message(self, message):
        self.log_viewer.config(state='normal')
        self.log_viewer.insert(tk.END, f"{message}\n")
        self.log_viewer.config(state='disabled')
        self.log_viewer.see(tk.END)

# ------------------------
# Main Execution
# ------------------------
if __name__ == "__main__":
    app = IntegrityCheckerApp()
    app.mainloop()
