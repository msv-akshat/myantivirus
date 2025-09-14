from tkinter import *
from tkinter import filedialog
import threading
import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import yara

# ---------------- Load YARA Rules ----------------
def load_rules():
    rules_folder = os.path.join(os.path.dirname(__file__), "rules")
    rule_files = [os.path.join(rules_folder, f) for f in os.listdir(rules_folder) if f.endswith(".yar")]
    compiled_rules = []
    for f in rule_files:
        try:
            compiled_rules.append(yara.compile(filepath=f))
        except yara.Error as e:
            print(f"Error compiling {f}: {e}")
    return compiled_rules

YARA_RULES = load_rules()

# ---------------- Scan Engine ----------------
def scan_file(file_path):
    matches = []
    try:
        for rule in YARA_RULES:
            result = rule.match(file_path)
            if result:
                matches.extend([r.rule for r in result])
    except Exception as e:
        matches.append(f"Error scanning {file_path}: {e}")
    return matches

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

def start_rtm(path, log_func, stop_flag):
    handler = RTMHandler(log_func)
    observer = Observer()
    observer.schedule(handler, path=path, recursive=True)
    observer.start()
    try:
        while not stop_flag["stop"]:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    observer.stop()
    observer.join()

# ---------------- GUI ----------------
class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Antivirus Demo with YARA")
        self.root.geometry("1000x700")
        self.file_path = ""
        self.rtm_thread = None
        self.rtm_stop_flag = {"stop": False}
        self.setup_ui()

    def setup_ui(self):
        Label(self.root, text="Python Antivirus Demo with YARA", font=("Helvetica", 24, "bold")).pack(pady=10)

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
            for root_dir, _, files in os.walk(self.file_path):
                for f in files:
                    full_path = os.path.join(root_dir, f)
                    matches = scan_file(full_path)
                    for m in matches:
                        self.output_text.insert(END, f"[+] {f} matched: {m}\n")

    # ---------------- RTM ----------------
    def toggle_rtm(self):
        if self.switch_var.get():
            if not self.file_path or not os.path.isdir(self.file_path):
                self.switch_var.set(0)
                return
            self.rtm_stop_flag["stop"] = False
            self.rtm_button.config(text="RTM ON")
            self.rtm_thread = threading.Thread(target=start_rtm,
                                               args=(self.file_path, self.log_rtm, self.rtm_stop_flag),
                                               daemon=True)
            self.rtm_thread.start()
        else:
            self.rtm_stop_flag["stop"] = True
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
