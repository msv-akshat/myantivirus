from tkinter import *
from tkinter import filedialog, messagebox
import threading
import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ---------------- Sample Rules Loader ----------------
def load_rules():
    import rules.sample_text as text_rule
    import rules.sample_webshell as web_rule
    import rules.sample_pe as pe_rule
    return text_rule.rules + web_rule.rules + pe_rule.rules

RULES = load_rules()

# ---------------- Scan Engine ----------------
def scan_file(file_path):
    results = []
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            for rule in RULES:
                if rule['pattern'].encode() in content:
                    results.append(rule['name'])
    except Exception as e:
        results.append(f"Error scanning {file_path}: {e}")
    return results

# ---------------- Real-Time Monitoring ----------------
class RTMHandler(FileSystemEventHandler):
    def __init__(self, log_func):
        super().__init__()
        self.log_func = log_func

    def on_created(self, event):
        if not event.is_directory:
            self.log_func(f"[RTM] New file detected: {event.src_path}")
            matches = scan_file(event.src_path)
            for m in matches:
                self.log_func(f"[RTM] Rule matched: {m}")

def start_rtm(path, log_func):
    handler = RTMHandler(log_func)
    observer = Observer()
    observer.schedule(handler, path=path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# ---------------- GUI ----------------
class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Antivirus Demo")
        self.root.geometry("1000x700")
        self.file_path = ""
        self.rtm_thread = None
        self.rtm_active = False
        self.setup_ui()

    def setup_ui(self):
        Label(self.root, text="Python Antivirus Demo", font=("Helvetica", 24, "bold")).pack(pady=10)

        # File selection
        frame = Frame(self.root)
        frame.pack(pady=10)

        Button(frame, text="Select File", command=self.open_file).grid(row=0, column=0, padx=5)
        Button(frame, text="Select Folder", command=self.open_folder).grid(row=0, column=1, padx=5)
        Button(frame, text="Scan", command=self.scan).grid(row=0, column=2, padx=5)

        self.file_label = Label(self.root, text="", font=("Helvetica", 12))
        self.file_label.pack(pady=5)

        # Scan output
        Label(self.root, text="Scan Output", font=("Helvetica", 16, "bold")).pack(pady=5)
        self.output_text = Text(self.root, width=120, height=10, bg="#262626", fg="white")
        self.output_text.pack(padx=10, pady=5)

        # RTM
        Label(self.root, text="Real-Time Monitoring", font=("Helvetica", 16, "bold")).pack(pady=10)
        self.rtm_text = Text(self.root, width=120, height=10, bg="#262626", fg="#00ff00")
        self.rtm_text.pack(padx=10, pady=5)
        self.switch_var = IntVar()
        self.rtm_button = Checkbutton(self.root, text="RTM OFF", variable=self.switch_var, indicatoron=False,
                                      command=self.toggle_rtm, width=20)
        self.rtm_button.pack(pady=5)

    # ---------------- File Selection ----------------
    def open_file(self):
        self.file_path = filedialog.askopenfilename()
        self.file_label.config(text=f"Selected: {self.file_path}")

    def open_folder(self):
        self.file_path = filedialog.askdirectory()
        self.file_label.config(text=f"Selected Folder: {self.file_path}")

    # ---------------- Scan ----------------
    def scan(self):
        if not self.file_path:
            return
        self.output_text.delete(1.0, END)
        if os.path.isfile(self.file_path):
            matches = scan_file(self.file_path)
            for m in matches:
                self.output_text.insert(END, f"[+] Rule matched: {m}\n")
        else:
            for f in os.listdir(self.file_path):
                full_path = os.path.join(self.file_path, f)
                if os.path.isfile(full_path):
                    matches = scan_file(full_path)
                    for m in matches:
                        self.output_text.insert(END, f"[+] {f} matched: {m}\n")

    # ---------------- RTM ----------------
    def toggle_rtm(self):
        if self.switch_var.get():
            if not self.file_path or not os.path.isdir(self.file_path):
                self.switch_var.set(0)
                return
            self.rtm_active = True
            self.rtm_button.config(text="RTM ON")
            self.rtm_thread = threading.Thread(target=start_rtm, args=(self.file_path, self.log_rtm), daemon=True)
            self.rtm_thread.start()
        else:
            self.rtm_active = False
            self.rtm_button.config(text="RTM OFF")
            self.rtm_text.insert(END, "\n[RTM Stopped]\n")

    def log_rtm(self, text):
        self.rtm_text.insert(END, text + "\n")
        self.rtm_text.see(END)

# ---------------- Main ----------------
if __name__ == "__main__":
    root = Tk()
    app = AntivirusGUI(root)
    root.mainloop()
