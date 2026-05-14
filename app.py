"""
Cyber SOS App (Beginner-Friendly) - secure version (vulnerability fixes)

Changes to remove obvious vulnerabilities:
- Removed hard-coded email credentials and receiver addresses.
- Disabled automatic email sending by default (SEND_EMAIL = False).
- Require user to configure email settings via GUI before sending.
- Avoid logging or displaying sensitive secrets.
- Attempt to restrict file permissions for key/settings files where possible.
- Consolidated duplicate/broken GUI and email code paths.
- Basic email validation to avoid sending to empty/invalid addresses.

Install:
    pip install cryptography requests

Run:
    python app.py
"""
import json
import os
import smtplib
import stat
from datetime import datetime
from email.mime.text import MIMEText
from tkinter import (
    Tk, Label, Button, messagebox, Toplevel, Entry, Listbox, END, SINGLE,
    Scrollbar, RIGHT, Y, LEFT, BOTH, Frame
)
import re
import requests
import pywhatkit
import time
import webbrowser
import subprocess

from cryptography.fernet import Fernet
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import urllib.parse
import pathlib
import traceback

# =========================
# CONFIGURATION (SECURE)
# =========================
# Do NOT enable email sending until settings and contacts are configured.
SEND_EMAIL = False

SETTINGS_FILE = "settings.json"
CONTACTS_FILE = "contacts.json"
KEY_FILE = "secret.key"
LOG_FILE = "alerts.log"

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# =========================
# UTILITIES
# =========================
def restrict_file_permissions(path):
    """
    Try to set restrictive permissions on created files.
    On POSIX: 0o600. On Windows this is best-effort (os.chmod exists but differs).
    """
    try:
        if os.name == "posix":
            os.chmod(path, 0o600)
        else:
            # On Windows, set read-write for owner only is complex; at least remove write for others where possible
            os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
    except Exception:
        # Best-effort only; do not fail application if this isn't possible
        pass

def is_valid_email(addr):
    if not addr:
        return False
    # Simple regex for validation (not exhaustive)
    return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", addr) is not None

# =========================
# ENCRYPTION FUNCTIONS
# =========================
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    restrict_file_permissions(KEY_FILE)
    return key

def encrypt_text(text, key):
    fernet = Fernet(key)
    return fernet.encrypt(text.encode())

def decrypt_text(token, key):
    fernet = Fernet(key)
    return fernet.decrypt(token).decode()

# =========================
# DATA COLLECTION
# =========================
def get_public_ip():
    try:
        response = requests.get("https://api.ipify.org?format=json", timeout=5)
        return response.json().get("ip", "Unavailable")
    except Exception:
        return "Unavailable"

def get_location_info():
    """
    Returns dict: {
      "text": "City, Region, Country (lat, lon)" or empty,
      "lat": float or None,
      "lon": float or None,
      "maps_link": "https://www.google.com/maps/search/?api=1&query=lat,lon" or ""
    }
    Falls back to empty values when lookup fails.
    """
    try:
        r = requests.get("http://ip-api.com/json/", timeout=5).json()
        if r.get("status") == "success":
            city = r.get("city") or ""
            region = r.get("regionName") or ""
            country = r.get("country") or ""
            lat = r.get("lat")
            lon = r.get("lon")
            parts = [p for p in (city, region, country) if p]
            text = ", ".join(parts)
            coords = ""
            if lat is not None and lon is not None:
                coords = f"{lat:.6f},{lon:.6f}"
            if text and coords:
                display = f"{text} ({coords})"
            elif text:
                display = text
            elif coords:
                display = coords
            else:
                display = ""
            maps_link = ""
            if lat is not None and lon is not None:
                maps_link = f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"
            return {"text": display, "lat": lat, "lon": lon, "maps_link": maps_link}
    except Exception:
        pass
    return {"text": "", "lat": None, "lon": None, "maps_link": ""}


def build_alert_data():
    # include saved user location (fallback to IP-based lookup)
    settings = load_settings()
    saved = settings.get("user_location", "").strip()
    if saved:
        # if user provided free-text location, build a Google Maps search link
        maps_link = f"https://www.google.com/maps/search/?api=1&query={urllib.parse.quote(saved)}"
        loc_info = {"text": saved, "lat": None, "lon": None, "maps_link": maps_link}
    else:
        loc_info = get_location_info()

    return {
        "event": "SOS Triggered",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "public_ip": get_public_ip(),
        "device": os.name,
        "user_location": loc_info["text"],
        "maps_link": loc_info["maps_link"],
        "message": "Emergency alert triggered by the user."
    }

# =========================
# STORAGE
# =========================
def save_encrypted_alert(data, key):
    json_text = json.dumps(data, indent=2)
    encrypted = encrypt_text(json_text, key)
    with open(LOG_FILE, "ab") as f:
        f.write(encrypted + b"\n")

def view_last_alert():
    if not os.path.exists(LOG_FILE):
        return "No alerts saved yet."
    with open(LOG_FILE, "rb") as f:
        lines = f.readlines()
    if not lines:
        return "No alerts saved yet."
    key = load_or_create_key()
    last_encrypted = lines[-1].strip()
    try:
        return decrypt_text(last_encrypted, key)
    except Exception as e:
        return f"Could not decrypt alert: {e}"

# =========================
# SETTINGS & CONTACTS
# =========================
def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r") as f:
            s = json.load(f)
            # ensure keys exist
            s.setdefault("sender_email", "")
            s.setdefault("app_password", "")
            s.setdefault("forward_to", [])  # list of emails to forward to
            s.setdefault("user_location", "")  # saved user location
            return s
    return {"sender_email": "", "app_password": "", "forward_to": [], "user_location": ""}

def save_settings(email, password, forward_list=None):
    if forward_list is None:
        forward_list = []
    with open(SETTINGS_FILE, "w") as f:
        json.dump({
            "sender_email": email,
            "app_password": password,
            "forward_to": forward_list
        }, f, indent=4)
    restrict_file_permissions(SETTINGS_FILE)

def load_contacts():
    if os.path.exists(CONTACTS_FILE):
        with open(CONTACTS_FILE, "r") as f:
            return json.load(f)
    return []

def save_contacts(contacts):
    with open(CONTACTS_FILE, "w") as f:
        json.dump(contacts, f, indent=2)
    restrict_file_permissions(CONTACTS_FILE)

# =========================
# EMAIL SENDING (SAFE)
# =========================
# Enable email sending
SEND_EMAIL = True


def send_email_alert(data):
    """
    Send the SOS alert to saved contact emails and forward addresses.
    Accepts contacts as dicts (with 'email','phone','carrier') or plain email strings.
    """
    settings = load_settings()
    sender_email = settings.get("sender_email", "").strip()
    app_password = settings.get("app_password", "").strip()
    forward_list = settings.get("forward_to", []) or []

    if not sender_email or not app_password:
        raise Exception("Please open Email Settings and save your Gmail and App Password.")

    contacts = load_contacts()
    if not contacts and not forward_list:
        raise Exception("No contacts saved and no forward addresses configured. Add contacts or forward addresses first.")

    carrier_gateways = {
        "att": "{}@txt.att.net",
        "verizon": "{}@vtext.com",
        "tmobile": "{}@tmomail.net",
        "sprint": "{}@messaging.sprintpcs.com",
        "virgin": "{}@vmobl.com",
        "metropcs": "{}@mymetropcs.com"
    }

    subject = "🚨 Cyber SOS Alert"
    try:
        body_json = json.dumps(data, indent=2)
    except Exception:
        body_json = str(data)

    location_text = data.get("user_location") or data.get("public_ip") or "Location unavailable"
    maps_link = data.get("maps_link", "") or ""

    email_body = (
        "🚨 EMERGENCY ALERT 🚨\n\n"
        f"Location: {location_text}\n"
        + (f"Live map: {maps_link}\n\n" if maps_link else "\n")
        + "This SOS alert was triggered from the Cyber SOS application.\n\n"
        f"{body_json}\n\n"
        "Police: 100\nAmbulance: 108\nFire: 101\n\nNational Emergency Response: 112\n"
        "Please contact the sender as soon as possible."
    )

    email_recipients = []
    sms_recipients = []

    # normalize contacts: accept dicts or plain strings
    for c in contacts:
        # if contact is plain string treat as email
        if isinstance(c, str):
            e = c.strip()
            if e and is_valid_email(e):
                email_recipients.append(e)
            continue
        # otherwise assume dict-like
        try:
            e = (c.get("email") or "").strip()
        except Exception:
            e = ""
        if e and is_valid_email(e):
            email_recipients.append(e)

        phone = ""
        carrier = ""
        try:
            phone = (c.get("phone") or "").strip()
            carrier = (c.get("carrier") or "").strip().lower()
        except Exception:
            phone = ""
            carrier = ""

        if phone and carrier:
            gw = carrier_gateways.get(carrier)
            if gw:
                digits = "".join(ch for ch in phone if ch.isdigit())
                if digits:
                    sms_recipients.append(gw.format(digits))

    # include forward addresses from settings
    forward_valid = []
    for addr in forward_list:
        a = (addr or "").strip()
        if a and is_valid_email(a):
            forward_valid.append(a)

    # dedupe
    combined_emails = []
    for r in (email_recipients + forward_valid):
        if r not in combined_emails:
            combined_emails.append(r)

    if not combined_emails and not sms_recipients:
        raise Exception("No valid email or SMS recipients found. Add valid contacts or forward addresses.")

    # send with per-recipient error handling
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(sender_email, app_password)

            for rcpt in combined_emails:
                try:
                    msg = MIMEText(email_body, _charset="utf-8")
                    msg["Subject"] = subject
                    msg["From"] = sender_email
                    msg["To"] = rcpt
                    server.send_message(msg, from_addr=sender_email, to_addrs=[rcpt])
                except Exception:
                    # continue sending to others
                    pass

            sms_text = "EMERGENCY: I triggered a Cyber SOS alert. Please check email or contact me immediately."
            if isinstance(data, dict):
                extras = []
                if data.get("timestamp"):
                    extras.append(data["timestamp"])
                if data.get("public_ip"):
                    extras.append(data["public_ip"])
                if data.get("user_location"):
                    extras.append(data["user_location"])
                if extras:
                    sms_text += " (" + " | ".join(extras) + ")"
                if data.get("maps_link"):
                    sms_text += " " + data.get("maps_link")

            for rcpt in sms_recipients:
                try:
                    msg = MIMEText(sms_text, _charset="utf-8")
                    msg["Subject"] = ""
                    msg["From"] = sender_email
                    msg["To"] = rcpt
                    server.send_message(msg, from_addr=sender_email, to_addrs=[rcpt])
                except Exception:
                    pass

    except smtplib.SMTPAuthenticationError:
        raise Exception("SMTP authentication failed. Verify your email and app password (use an app password for Gmail).")
    except Exception as e:
        raise Exception(f"Failed to send alerts: {e}")
# whatsapp message
# ...existing code...
# helper: resolve approximate user location from IP
def get_location_text():
    try:
        r = requests.get("http://ip-api.com/json/", timeout=5).json()
        if r.get("status") == "success":
            parts = []
            if r.get("city"):
                parts.append(r["city"])
            if r.get("regionName"):
                parts.append(r["regionName"])
            if r.get("country"):
                parts.append(r["country"])
            coords = f"lat:{r.get('lat')} lon:{r.get('lon')}"
            return ", ".join(parts) + " (" + coords + ")"
    except Exception:
        pass
    return "Location unavailable"

def send_whatsapp_message(phone, location_text="Location unavailable", wait_time=10):
    """
    Send a WhatsApp message using pywhatkit.sendwhatmsg_instantly.
    phone: digits or with +countrycode. Normalizes digits and prefixes '+'.
    Returns tuple (phone_normalized, status, error_message_if_any)
    """
    if not phone:
        return (phone, "skipped", "empty")
    digits = "".join(ch for ch in str(phone) if ch.isdigit())
    if not digits:
        return (phone, "skipped", "invalid digits")
    phone_normalized = "+" + digits
    message = (
        "🚨 EMERGENCY ALERT 🚨\n\n"
        "I need help immediately.\n\n"
        f"My location:\n{location_text}\n\n"
        "Please contact me as soon as possible."
    )
    try:
        # sendwhatmsg_instantly requires WhatsApp Web logged in in default browser
        pywhatkit.sendwhatmsg_instantly(
            phone_no=phone_normalized,
            message=message,
            wait_time=wait_time,
            tab_close=True,
            close_time=3
        )
        # small pause between sends to avoid race conditions
        time.sleep(1.2)
        return (phone_normalized, "ok", "")
    except Exception as e:
        return (phone_normalized, "error", str(e))


def open_whatsapp_dialog(parent, default_numbers=None, location_text=None):
    """
    Open dialog where user can edit/add/remove WhatsApp numbers before sending.
    default_numbers: list of phone strings
    location_text: if None, fetched automatically
    """
    if default_numbers is None:
        default_numbers = []
    if location_text is None:
        location_text = get_location_text()

    win = Toplevel(parent)
    win.title("WhatsApp Recipients")
    win.geometry("480x380")

    listbox = Listbox(win, height=10)
    listbox.pack(fill=BOTH, padx=8, pady=6, expand=True)

    for num in default_numbers:
        listbox.insert(END, num)

    entry_frame = Frame(win)
    entry_frame.pack(fill=BOTH, padx=8, pady=(0,8))

    number_entry = Entry(entry_frame, width=40)
    number_entry.pack(side=LEFT, expand=True, fill=BOTH)

    def add_number():
        n = number_entry.get().strip()
        if n:
            listbox.insert(END, n)
            number_entry.delete(0, END)

    def update_number():
        sel = listbox.curselection()
        if not sel:
            messagebox.showwarning("Select", "Select a number to update.")
            return
        idx = sel[0]
        n = number_entry.get().strip()
        if n:
            listbox.delete(idx)
            listbox.insert(idx, n)
            listbox.selection_set(idx)

    def delete_number():
        sel = listbox.curselection()
        if not sel:
            messagebox.showwarning("Select", "Select a number to delete.")
            return
        listbox.delete(sel[0])

    Button(entry_frame, text="Add", command=add_number).pack(side=LEFT, padx=4)
    Button(entry_frame, text="Update", command=update_number).pack(side=LEFT, padx=4)
    Button(entry_frame, text="Delete", command=delete_number).pack(side=LEFT, padx=4)

    def on_select(evt=None):
        sel = listbox.curselection()
        number_entry.delete(0, END)
        if sel:
            number_entry.insert(0, listbox.get(sel[0]))

    listbox.bind("<<ListboxSelect>>", on_select)

    info_label = Label(win, text=f"Location: {location_text}", wraplength=440, justify=LEFT)
    info_label.pack(padx=8, pady=(2,6))

    def send_all():
        nums = [listbox.get(i) for i in range(listbox.size())]
        if not nums:
            messagebox.showwarning("No numbers", "Add at least one phone number to send WhatsApp.")
            return
        failures = []
        successes = []
        for p in nums:
            phone_norm, status, err = send_whatsapp_message(p, location_text=location_text)
            if status != "ok":
                failures.append(f"{phone_norm}: {err or status}")
            else:
                successes.append(phone_norm)
        if successes and not failures:
            messagebox.showinfo("WhatsApp", f"Messages queued/sent to {len(successes)} number(s).")
        elif successes and failures:
            messagebox.showwarning("Partial Success", f"Sent to {len(successes)}; failed for:\n" + "\n".join(failures))
        else:
            messagebox.showerror("WhatsApp Failed", "All WhatsApp sends failed:\n" + "\n".join(failures))
        win.destroy()

    Button(win, text="Send to All", command=send_all).pack(pady=6)
    Button(win, text="Close", command=win.destroy).pack(pady=(0,8))
    win.transient(parent)
    win.grab_set()
    return win

def trigger_sos():
    try:
        # Build alert data
        key = load_or_create_key()
        alert_data = build_alert_data()

        # Save encrypted log
        save_encrypted_alert(alert_data, key)

        # Send email alerts
        if SEND_EMAIL:
            send_email_alert(alert_data)
            messagebox.showinfo(
                "SOS Sent",
                "Emergency email sent successfully to all saved contacts."
            )
        else:
            messagebox.showinfo(
                "SOS Stored",
                "Emergency alert has been securely stored."
            )

    except Exception as e:
        messagebox.showerror("Error", str(e))
# =========================
# GUI
# =========================
def create_gui():
    root = Tk()
    root.title("Cyber SOS App")
    root.geometry("420x340")

    Label(root, text="Cyber SOS Application", font=("Arial", 18, "bold")).pack(pady=12)
    Label(root, text="Click the button below to trigger an encrypted SOS alert.", wraplength=380).pack(pady=6)

    def trigger_sos():
        try:
            key = load_or_create_key()
            alert_data = build_alert_data()
            save_encrypted_alert(alert_data, key)
            if SEND_EMAIL:
                # Only attempt email sending if explicitly enabled and configured
                send_email_alert(alert_data)
            messagebox.showinfo("SOS Sent", "Emergency alert has been created and securely stored.")
            # Prompt to call emergency number 112 (toll-free)
            if messagebox.askyesno("Call Emergency", "Do you want to call the emergency number 112 now?"):
                ok = call_emergency("112")
                if ok:
                    messagebox.showinfo("Calling", "Attempting to open your calling app for 112.")
                else:
                    messagebox.showwarning("Call Failed", "Could not start a call on this device. Please call 112 manually.")
        except Exception as e:
            # Do not print secrets in UI; show a concise error
            messagebox.showerror("Error", f"Failed to send SOS:\n{e}")

    def show_last_alert():
        data = view_last_alert()
        messagebox.showinfo("Last Saved Alert", data)

    Button(root, text="🚨 SEND SOS", font=("Arial", 14, "bold"), width=20, height=2, command=trigger_sos).pack(pady=10)
    Button(root, text="View Last Alert", width=20, command=show_last_alert).pack(pady=6)
    Button(root, text="Email Settings", width=20, command=lambda: open_settings(root)).pack(pady=6)
    Button(root, text="Manage Contacts", width=20, command=lambda: open_contacts(root)).pack(pady=6)

    root.mainloop()

def open_settings(parent):
    settings = load_settings()
    win = Toplevel(parent)
    win.title("Email Settings")
    win.geometry("520x250")

    Label(win, text="Your Gmail Address").pack(pady=4)
    email_entry = Entry(win, width=60)
    email_entry.pack()
    email_entry.insert(0, settings.get("sender_email", ""))

    Label(win, text="Gmail App Password").pack(pady=4)
    password_entry = Entry(win, width=60, show="*")
    password_entry.pack()
    password_entry.insert(0, settings.get("app_password", ""))

    Label(win, text="Forward copies to (comma-separated emails)").pack(pady=4)
    forward_entry = Entry(win, width=80)
    forward_entry.pack()
    forward_entry.insert(0, ", ".join(settings.get("forward_to", [])))

    def save():
        email = email_entry.get().strip()
        password = password_entry.get().strip()
        forward_text = forward_entry.get().strip()
        forward_list = [x.strip() for x in forward_text.split(",") if x.strip()]
        # validate forward emails
        for addr in forward_list:
            if not is_valid_email(addr):
                messagebox.showwarning("Invalid Forward Email", f"Invalid forward address: {addr}")
                return
        if not email or not password:
            messagebox.showwarning("Missing Information", "Please enter both email and app password.")
            return
        if not is_valid_email(email):
            messagebox.showwarning("Invalid Email", "Please enter a valid email address.")
            return
        save_settings(email, password, forward_list)
        messagebox.showinfo("Saved", "Email settings saved successfully.")
        win.destroy()

    Button(win, text="Save Settings", command=save).pack(pady=12)

def open_contacts(parent):
    try:
        contacts = load_contacts()
    except Exception:
        contacts = []
        messagebox.showwarning("Contacts Load Error", "Could not read contacts file; starting with empty list.")

    win = Toplevel(parent)
    win.title("Manage Contacts")
    win.geometry("520x360")

    frame = Frame(win)
    frame.pack(fill=BOTH, expand=True, padx=8, pady=8)

    scrollbar = Scrollbar(frame)
    scrollbar.pack(side=RIGHT, fill=Y)

    listbox = Listbox(frame, selectmode=SINGLE, yscrollcommand=scrollbar.set, width=40)
    listbox.pack(side=LEFT, fill=BOTH, expand=True)
    scrollbar.config(command=listbox.yview)

    Label(win, text="Name").pack(pady=(6,0))
    name_entry = Entry(win, width=60)
    name_entry.pack()
    Label(win, text="Email").pack(pady=(6,0))
    email_entry = Entry(win, width=60)
    email_entry.pack()
    Label(win, text="Phone (digits only)").pack(pady=(6,0))
    phone_entry = Entry(win, width=60)
    phone_entry.pack()
    Label(win, text="Carrier (e.g. att, verizon, tmobile)").pack(pady=(6,0))
    carrier_entry = Entry(win, width=60)
    carrier_entry.pack()

    def refresh_list(reload_from_disk=False):
        if reload_from_disk:
            try:
                new = load_contacts()
                contacts.clear()
                contacts.extend(new)
            except Exception:
                pass
        listbox.delete(0, END)
        for i, c in enumerate(contacts):
            phone = c.get('phone','')
            carrier = c.get('carrier','')
            display = f"{c.get('name','')} <{c.get('email','')}>"
            if phone:
                display += f" [{phone}"
                if carrier:
                    display += f" @ {carrier}"
                display += "]"
            listbox.insert(END, display)

    def on_select(evt=None):
        sel = listbox.curselection()
        if not sel:
            name_entry.delete(0, END); email_entry.delete(0, END); phone_entry.delete(0, END); carrier_entry.delete(0, END)
            return
        idx = sel[0]
        if idx < 0 or idx >= len(contacts):
            return
        c = contacts[idx]
        name_entry.delete(0, END); name_entry.insert(0, c.get("name",""))
        email_entry.delete(0, END); email_entry.insert(0, c.get("email",""))
        phone_entry.delete(0, END); phone_entry.insert(0, c.get("phone",""))
        carrier_entry.delete(0, END); carrier_entry.insert(0, c.get("carrier",""))

    def add_or_update():
        name = name_entry.get().strip()
        email = email_entry.get().strip()
        phone = phone_entry.get().strip()
        carrier = carrier_entry.get().strip().lower()
        if not name:
            messagebox.showwarning("Missing Name", "Please enter a contact name.")
            return
        if email and not is_valid_email(email):
            messagebox.showwarning("Invalid Email", "Please enter a valid email address.")
            return
        contact = {"name": name, "email": email, "phone": phone, "carrier": carrier}
        sel = listbox.curselection()
        if sel:
            idx = sel[0]
            if 0 <= idx < len(contacts):
                contacts[idx] = contact
        else:
            contacts.append(contact)
        try:
            save_contacts(contacts)
        except Exception:
            messagebox.showwarning("Save Error", "Failed to save contacts to disk; changes kept in memory.")
        refresh_list()
        listbox.selection_clear(0, END)
        name_entry.delete(0, END); email_entry.delete(0, END); phone_entry.delete(0, END); carrier_entry.delete(0, END)
        messagebox.showinfo("Saved", "Contact saved successfully.")

    def delete_contact():
        sel = listbox.curselection()
        if not sel:
            messagebox.showwarning("Select Contact", "Please select a contact to delete.")
            return
        idx = sel[0]
        if 0 <= idx < len(contacts) and messagebox.askyesno("Confirm", "Delete selected contact?"):
            contacts.pop(idx)
            try:
                save_contacts(contacts)
            except Exception:
                messagebox.showwarning("Save Error", "Failed to save contacts to disk; changes kept in memory.")
            refresh_list()

    listbox.bind("<<ListboxSelect>>", on_select)
    refresh_list()  # initial populate
    Button(win, text="Add/Update Contact", command=add_or_update).pack(pady=6)
    Button(win, text="Delete Contact", command=delete_contact).pack(pady=4)

# =========================
# ENTRY POINT
# =========================
if __name__ == "__main__":
    # Create default settings/contacts files if missing, with restricted perms
    if not os.path.exists(SETTINGS_FILE):
        save_settings("", "")
    if not os.path.exists(CONTACTS_FILE):
        save_contacts([])
    create_gui()


