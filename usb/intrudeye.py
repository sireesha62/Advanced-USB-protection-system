import wmi
import os
import time
import tkinter as tk
from tkinter import simpledialog, messagebox
import cv2
import smtplib
from email.message import EmailMessage
from datetime import datetime
import webbrowser
from PIL import Image, ImageTk
import winreg
import subprocess
import threading

# --- CONFIGURATION ---
PASSWORD = "secure123"  # Change this to your desired password
OWNER_EMAIL = "renukaulusu@gmail.com"  # Change to your email
EMAIL_PASSWORD = "owyr dvct eoap zdif"  # Use app password for Gmail
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
LOG_FILE = "event_log.txt"
PHOTO_FILE = "intruder.jpg"

# --- LOGGING ---
def log_event(event, status):
    with open(LOG_FILE, 'a') as f:
        f.write(f"{datetime.now()} | {event} | {status}\n")

# --- EMAIL ALERT ---
def send_email_with_photo(photo_path):
    msg = EmailMessage()
    msg['Subject'] = 'IntrudEye Alert: Intruder Detected'
    msg['From'] = OWNER_EMAIL
    msg['To'] = OWNER_EMAIL
    msg.set_content('An unauthorized USB access attempt was detected.')
    with open(photo_path, 'rb') as f:
        img_data = f.read()
        msg.add_attachment(img_data, maintype='image', subtype='jpeg', filename='intruder.jpg')
    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.login(OWNER_EMAIL, EMAIL_PASSWORD)
            smtp.send_message(msg)
        log_event('Email sent', 'Success')
    except Exception as e:
        log_event(f'Email failed: {e}', 'Fail')

# --- PHOTO CAPTURE ---
def capture_photo(filename=PHOTO_FILE):
    cam = cv2.VideoCapture(0)
    ret, frame = cam.read()
    if ret:
        cv2.imwrite(filename, frame)
        log_event('Photo captured', 'Success')
    else:
        log_event('Photo capture failed', 'Fail')
    cam.release()

# --- USB ACCESS CONTROL ---
def remove_drive_letter(drive_letter):
    c = wmi.WMI()
    for vol in c.Win32_Volume():
        if vol.DriveLetter and vol.DriveLetter.replace(':', '').upper() == drive_letter.upper():
            label = vol.Label or vol.DeviceID
            # Use diskpart to list volumes and find the volume number
            with open('diskpart_script.txt', 'w') as f:
                f.write('list volume\n')
            with open('volumes_output.txt', 'w') as out:
                subprocess.run(['diskpart', '/s', 'diskpart_script.txt'], stdout=out, stderr=subprocess.STDOUT)
            os.remove('diskpart_script.txt')
            with open('volumes_output.txt', 'r') as f:
                lines = f.readlines()
            os.remove('volumes_output.txt')
            vol_num = None
            for line in lines:
                if drive_letter.upper() + ':' in line:
                    try:
                        vol_num = int(line.strip().split()[1])
                        break
                    except Exception:
                        continue
            if vol_num is not None:
                with open('diskpart_script.txt', 'w') as f:
                    f.write(f"select volume {vol_num}\nremove letter={drive_letter}\n")
                subprocess.run(['diskpart', '/s', 'diskpart_script.txt'])
                os.remove('diskpart_script.txt')
                log_event(f'Removed drive letter {drive_letter} (Volume {vol_num}, {label})', 'Blocked')
            else:
                log_event(f'Could not find volume number for {drive_letter}', 'Fail')
            break
    else:
        log_event(f'No volume found for drive letter {drive_letter}', 'Fail')

def assign_drive_letter(volume, drive_letter):
    # Assign drive letter using diskpart
    script = f"assign letter={drive_letter}"
    with open('diskpart_script.txt', 'w') as f:
        f.write(f"select volume {volume}\n{script}\n")
    os.system('diskpart /s diskpart_script.txt')
    os.remove('diskpart_script.txt')
    log_event(f'Assigned drive letter {drive_letter} to volume {volume}', 'Enabled')

def set_usbstor_value(value):
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\USBSTOR",
            0,
            winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        return True
    except Exception as e:
        print(f"Error setting USBSTOR: {e}")
        return False

def get_volume_number(drive_letter):
    with open('diskpart_script.txt', 'w') as f:
        f.write('list volume\n')
    with open('volumes_output.txt', 'w') as out:
        subprocess.run(['diskpart', '/s', 'diskpart_script.txt'], stdout=out, stderr=subprocess.STDOUT)
    os.remove('diskpart_script.txt')
    with open('volumes_output.txt', 'r') as f:
        lines = f.readlines()
    os.remove('volumes_output.txt')

    for line in lines:
        if drive_letter + ':' in line:
            try:
                return int(line.strip().split()[1])
            except:
                continue
    return None

def get_usbstor_value():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\USBSTOR",
            0,
            winreg.KEY_READ
        )
        value, _ = winreg.QueryValueEx(key, "Start")
        winreg.CloseKey(key)
        return value
    except Exception as e:
        print(f"Error reading USBSTOR: {e}")
        return None

# --- USB CONTROL POPUP ---
def usb_control_popup(parent):
    result = {}
    popup = tk.Toplevel(parent)
    popup.title("USB Control")
    popup.geometry('340x200')
    popup.resizable(False, False)
    popup.configure(bg="#f4f6fa")
    popup.attributes('-topmost', True)

    label = tk.Label(
        popup, text="USB Storage Control", font=("Segoe UI", 15, "bold"), fg="#2a3b4c", bg="#f4f6fa"
    )
    label.pack(pady=(20, 8))

    btn_frame = tk.Frame(popup, bg="#f4f6fa")
    btn_frame.pack(pady=(8, 0))

    def style_btn(btn, color, hover_color):
        btn.configure(
            font=("Segoe UI", 10, "bold"),
            bg=color, fg="white",
            activebackground=hover_color, activeforeground="white",
            relief=tk.FLAT, bd=0, padx=6, pady=3, cursor="hand2",
            highlightthickness=0
        )
        # Add rounded corners (Windows only, best effort)
        try:
            btn.tk.call("tk::unsupported::MacWindowStyle", "style", btn._w, "rounded", "none")
        except Exception:
            pass

    def enable_usb():
        success = set_usbstor_value(3)
        if not success:
            messagebox.showerror("Error", "Failed to set USBSTOR to 3. Please run as administrator.", parent=popup)
        result["action"] = "enable"
        popup.destroy()

    def disable_usb():
        success = set_usbstor_value(4)
        if not success:
            messagebox.showerror("Error", "Failed to set USBSTOR to 4. Please run as administrator.", parent=popup)
        result["action"] = "disable"
        popup.destroy()

    btn_enable = tk.Button(btn_frame, text="Enable USB", width=10, command=enable_usb)
    style_btn(btn_enable, "#4CAF50", "#388E3C")
    btn_enable.grid(row=0, column=0, padx=12)

    btn_disable = tk.Button(btn_frame, text="Disable USB", width=10, command=disable_usb)
    style_btn(btn_disable, "#F44336", "#B71C1C")
    btn_disable.grid(row=0, column=1, padx=12)

    popup.grab_set()
    parent.wait_window(popup)
    return result.get("action")

# --- PASSWORD PROMPT (WITH PARENT, SHOW/HIDE CHECKBOX) ---
def ask_password_with_parent(parent):
    password = None
    popup = tk.Toplevel(parent)
    popup.title("IntrudEye - USB Authentication")
    popup.geometry('370x370')
    popup.resizable(False, False)
    popup.configure(bg="#f4f6fa")
    popup.attributes('-topmost', True)

    photo_ref = None
    try:
        img = Image.open("intrudeye.jpg")
        img = img.resize((80, 80), Image.Resampling.LANCZOS)
        photo = ImageTk.PhotoImage(img)
        icon_label = tk.Label(popup, image=photo, bg="#f4f6fa")
        photo_ref = photo
        icon_label.pack(pady=(18, 5))
    except Exception as e:
        icon_label = tk.Label(popup, text="[Icon Missing]", font=("Segoe UI", 12, "italic"), bg="#f4f6fa")
        icon_label.pack(pady=(18, 5))

    def show_info():
        webbrowser.open('project_info.html')

    info_btn = tk.Button(popup, text="Project Info", command=show_info, font=("Segoe UI", 10), bg="#e0e7ef", fg="#2a3b4c", relief=tk.FLAT, cursor="hand2")
    info_btn.pack(pady=(0, 15))

    tk.Label(popup, text="Enter USB access password:", font=("Segoe UI", 11), bg="#f4f6fa", fg="#2a3b4c").pack(pady=(0, 0))

    pw_frame = tk.Frame(popup, bg="#f4f6fa")
    pw_frame.pack(pady=8)
    entry = tk.Entry(pw_frame, show='*', width=22, font=("Segoe UI", 12))
    entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
    entry.focus_set()

    show_pw_var = tk.BooleanVar(value=False)
    def toggle_password():
        entry.config(show='' if show_pw_var.get() else '*')

    show_checkbox = tk.Checkbutton(
        pw_frame, text="Show Password", variable=show_pw_var, command=toggle_password,
        font=("Segoe UI", 10), bg="#f4f6fa", fg="#2a3b4c", activebackground="#f4f6fa", activeforeground="#2a3b4c"
    )
    show_checkbox.pack(side=tk.LEFT, padx=(8, 0))

    def on_submit():
        nonlocal password
        password = entry.get()
        popup.destroy()

    submit_btn = tk.Button(popup, text="Submit", command=on_submit, font=("Segoe UI", 12, "bold"), bg="#3a7bd5", fg="white", activebackground="#285a99", activeforeground="white", relief=tk.RAISED, bd=2, padx=10, pady=4, cursor="hand2")
    submit_btn.pack(pady=(16, 0))

    popup.protocol("WM_DELETE_WINDOW", popup.destroy)
    popup.grab_set()
    parent.wait_window(popup)
    return password

def get_connected_usb_devices():
    try:
        c = wmi.WMI()
        devices = set()
        for device in c.Win32_DiskDrive():
            if device.InterfaceType and 'USB' in device.InterfaceType.upper():
                devices.add(device.PNPDeviceID)
        return devices
    except Exception as e:
        print(f"[IntrudEye] Error getting USB devices: {e}")
        return set()

def initial_usb_prompt_flow():
    root = tk.Tk()
    root.withdraw()
    action = usb_control_popup(root)

    if action == "enable":
        set_usbstor_value(4)  # Set to disabled before verifying
        password = ask_password_with_parent(root)
        if password == PASSWORD:
            set_usbstor_value(3)  # Enable USB on successful password
            messagebox.showinfo("IntrudEye", "USB has been enabled successfully.", parent=root)
            log_event("USB enabled after auth", "Success")
        else:
            log_event("Enable attempt failed - wrong password", "Intruder")
            capture_photo()
            send_email_with_photo(PHOTO_FILE)
            messagebox.showerror("IntrudEye", "Incorrect password. Access denied.", parent=root)

    elif action == "disable":
        set_usbstor_value(3)  # Temporarily ensure it's enabled to access prompt
        password = ask_password_with_parent(root)
        if password == PASSWORD:
            set_usbstor_value(4)  # Disable USB after correct password
            messagebox.showinfo("IntrudEye", "USB has been disabled successfully.", parent=root)
            log_event("USB disabled after auth", "Success")
        else:
            log_event("Disable attempt failed - wrong password", "Intruder")
            capture_photo()
            send_email_with_photo(PHOTO_FILE)
            messagebox.showerror("IntrudEye", "Incorrect password. Access denied.", parent=root)
    root.destroy()

def handle_usb_hardware_insert(device_id):
    root = tk.Tk()
    root.withdraw()
    action = usb_control_popup(root)
    if action in ("enable", "disable"):
        password = ask_password_with_parent(root)
        if password == PASSWORD:
            if action == "enable":
                set_usbstor_value(3)
                messagebox.showinfo("IntrudEye", "USB storage enabled. Please re-insert your USB device.", parent=root)
            elif action == "disable":
                set_usbstor_value(4)
                log_event('USB access disabled by user', 'Info')
                messagebox.showinfo("IntrudEye", "USB access is now disabled.", parent=root)
        else:
            log_event('USB access denied', 'Intruder')
            capture_photo()
            send_email_with_photo(PHOTO_FILE)
            messagebox.showerror("IntrudEye", "Incorrect password. Access denied.", parent=root)
    root.destroy()

def test_usb_detection():
    """Test function to check if USB detection is working"""
    print("\n=== USB Detection Test ===")
    
    # Check USBSTOR value
    usbstor_val = get_usbstor_value()
    print(f"USBSTOR value: {usbstor_val}")
    
    # Check current USB devices
    devices = get_connected_usb_devices()
    print(f"Current USB devices: {len(devices)}")
    for device in devices:
        print(f"  - {device}")
    
    # Test WMI connection
    try:
        c = wmi.WMI()
        disk_drives = c.Win32_DiskDrive()
        print(f"Total disk drives: {len(disk_drives)}")
        for drive in disk_drives:
            print(f"  - {drive.Caption} (Interface: {drive.InterfaceType})")
    except Exception as e:
        print(f"WMI error: {e}")
    
    print("=== Test Complete ===\n")

# --- TEST EMAIL FUNCTION ---
def send_test_email():
    test_photo = PHOTO_FILE
    # Create a dummy photo if it doesn't exist
    if not os.path.exists(test_photo):
        import numpy as np
        import cv2
        dummy_img = np.zeros((100, 100, 3), dtype=np.uint8)
        cv2.putText(dummy_img, 'TEST', (10, 60), cv2.FONT_HERSHEY_SIMPLEX, 1.5, (255,255,255), 2)
        cv2.imwrite(test_photo, dummy_img)
    try:
        send_email_with_photo(test_photo)
        print("Test email sent (check your inbox and event_log.txt)")
    except Exception as e:
        print(f"Test email failed: {e}")

# --- TEST PLAIN EMAIL FUNCTION ---
def send_test_email_plain():
    from email.mime.text import MIMEText
    msg = EmailMessage()
    msg['Subject'] = 'IntrudEye Test: Plain Email Only'
    msg['From'] = OWNER_EMAIL
    msg['To'] = OWNER_EMAIL
    msg.set_content('This is a test email from IntrudEye (plain, no attachment).')
    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.login(OWNER_EMAIL, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print("Plain test email sent (check your inbox and event_log.txt)")
        log_event('Plain test email sent', 'Success')
    except Exception as e:
        print(f"Plain test email failed: {e}")
        log_event(f'Plain test email failed: {e}', 'Fail')
    
def monitor_usb():
    log_event("Monitor started", "Info")
    print("[IntrudEye] Starting USB monitoring...")

    previous_devices = get_connected_usb_devices()
    print(f"[IntrudEye] Initial USB devices found: {len(previous_devices)}")

    while True:
        try:
            time.sleep(1)
            current_devices = get_connected_usb_devices()
            inserted = current_devices - previous_devices

            if inserted:
                print(f"[IntrudEye] New USB device(s) detected: {len(inserted)}")
                for device_id in inserted:
                    print(f"[IntrudEye] Device ID: {device_id}")
                    log_event(f'USB device detected: {device_id}', 'Detected')
                    handle_usb_hardware_insert(device_id)

            previous_devices = current_devices

        except Exception as e:
            print(f"[IntrudEye] Error in monitoring loop: {e}")
            log_event(f'Monitoring error: {e}', 'Error')
            time.sleep(5)

if __name__ == "__main__":
    import sys
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "--test-email":
            send_test_email()
        elif len(sys.argv) > 1 and sys.argv[1] == "--test-email-plain":
            send_test_email_plain()
        else:
            test_usb_detection()
            initial_usb_prompt_flow()  # Run your updated popup + auth flow
            monitor_usb()  # Start background USB monitoring
    except Exception as e:
        log_event(f'Fatal error: {e}', 'Fail')
        print(f"[IntrudEye] Error: {e}")

