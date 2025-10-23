#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext
import subprocess
import threading
import queue
import psutil
import sys
import os

class ServerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PyTunnel Server Control")
        self.server_process = None
        self.log_queue = queue.Queue()
        self.cpu_queue = queue.Queue()

        # --- UI Elements ---
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

        # Control Frame
        control_frame = ttk.LabelFrame(main_frame, text="Controls", padding="10")
        control_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E))
        control_frame.columnconfigure(1, weight=1)

        self.start_stop_button = ttk.Button(control_frame, text="Start Server", command=self.toggle_server)
        self.start_stop_button.grid(row=0, column=0, padx=5, pady=5)

        self.vulnerable_mode = tk.BooleanVar()
        self.vulnerable_check = ttk.Checkbutton(control_frame, text="Run in Vulnerable Mode", variable=self.vulnerable_mode)
        self.vulnerable_check.grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(control_frame, text="Log Level:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.loglevel_var = tk.StringVar(value='INFO')
        self.loglevel_combo = ttk.Combobox(
            control_frame, 
            textvariable=self.loglevel_var, 
            values=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
            state="readonly"
        )
        self.loglevel_combo.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        # Log Frame
        log_frame = ttk.LabelFrame(main_frame, text="Server Logs", padding="10")
        log_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)

        self.log_display = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state='disabled', height=15, width=80)
        self.log_display.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Status Frame
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding="10")
        status_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E))
        status_frame.columnconfigure(0, weight=1)

        self.cpu_label = ttk.Label(status_frame, text="CPU Usage: --%")
        self.cpu_label.grid(row=0, column=0, sticky=tk.W)

        # --- Start background tasks ---
        self.root.after(100, self.process_log_queue)
        self.monitor_cpu()

    def toggle_server(self):
        if self.server_process:
            self.stop_server()
        else:
            self.start_server()

    def start_server(self):
        self.log_message("--- Starting server... ---")
        self.start_stop_button.config(text="Stop Server")
        self.vulnerable_check.config(state='disabled')
        self.loglevel_combo.config(state='disabled')

        command = [sys.executable, '-u', '-m', 'src.pytunnel.cli.server_cli', '--config', 'configs/server.yaml', '--loglevel', self.loglevel_var.get()]
        if self.vulnerable_mode.get():
            command.append('--vulnerable')

        # Use sudo for network permissions. This may prompt for a password in the terminal
        # where the UI was launched.
        full_command = command
        
        try:
            # We use Popen to run in the background.
            # We capture stdout and stderr to display in our log.
            self.server_process = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
                preexec_fn=os.setsid # To kill the whole process group
            )
        except FileNotFoundError:
            self.log_message("ERROR: 'sudo' command not found. Please run this UI with sudo privileges.")
            self.stop_server()
            return
        except Exception as e:
            self.log_message(f"ERROR starting server: {e}")
            self.stop_server()
            return


        # Start threads to read stdout and stderr without blocking the UI
        threading.Thread(target=self.enqueue_output, args=(self.server_process.stdout, self.log_queue), daemon=True).start()
        threading.Thread(target=self.enqueue_output, args=(self.server_process.stderr, self.log_queue), daemon=True).start()

    def stop_server(self):
        if self.server_process:
            self.log_message("--- Stopping server... ---")
            try:
                # Kill the entire process group started with os.setsid
                subprocess.run(['kill', '--', f'-{os.getpgid(self.server_process.pid)}'])
            except Exception as e:
                self.log_message(f"Error trying to kill process: {e}")
            self.server_process.wait()
        self.server_process = None
        self.start_stop_button.config(text="Start Server")
        self.vulnerable_check.config(state='normal')
        self.loglevel_combo.config(state='readonly')
        self.log_message("--- Server stopped. ---")

    def enqueue_output(self, pipe, queue):
        """Reads lines from a pipe and puts them in a queue."""
        try:
            for line in iter(pipe.readline, ''):
                queue.put(line)
        finally:
            pipe.close()

    def process_log_queue(self):
        """Processes messages from the log queue and updates the UI."""
        while not self.log_queue.empty():
            line = self.log_queue.get_nowait()
            self.log_message(line.strip())
        self.root.after(100, self.process_log_queue)

    def log_message(self, message):
        print(message) # Print to terminal
        self.log_display.config(state='normal')
        self.log_display.insert(tk.END, message + '\n')
        self.log_display.see(tk.END)
        self.log_display.config(state='disabled')

    def monitor_cpu(self):
        """Monitors CPU usage in a separate thread."""
        def cpu_worker():
            while True:
                cpu_percent = psutil.cpu_percent(interval=1)
                self.cpu_queue.put(cpu_percent)

        threading.Thread(target=cpu_worker, daemon=True).start()
        self.root.after(1000, self.update_cpu_label)

    def update_cpu_label(self):
        """Updates the CPU label from the queue."""
        while not self.cpu_queue.empty():
            cpu_percent = self.cpu_queue.get_nowait()
            self.cpu_label.config(text=f"CPU Usage: {cpu_percent:.1f}%")
        self.root.after(1000, self.update_cpu_label)

    def on_closing(self):
        self.stop_server()
        self.root.destroy()

if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.stderr.write("This script must be run as root to create network interfaces.\n")
        sys.exit(1)
        
    root = tk.Tk()
    app = ServerUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
