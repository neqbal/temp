#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext
import subprocess
import threading
import queue
import sys
import os
import yaml

class ClientUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PyTunnel Client Control")
        self.client_process = None
        self.attack_process = None
        self.replay_attack_process = None
        self.log_queue = queue.Queue()
        self.config = self.load_client_config()
        self.server_addr = f"{self.config['server_addr']}:{self.config['server_port']}" if self.config else "N/A"

        # --- UI Elements ---
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)

        # Control Frame
        control_frame = ttk.LabelFrame(main_frame, text="Controls", padding="10")
        control_frame.grid(row=0, column=0, sticky=(tk.W, tk.E))

        ttk.Label(control_frame, text="Server Address:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.server_addr_var = tk.StringVar(value=f"{self.server_addr}")
        self.server_addr_entry = ttk.Entry(control_frame, textvariable=self.server_addr_var, width=30)
        self.server_addr_entry.grid(row=0, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))
        control_frame.columnconfigure(1, weight=1)

        self.connect_button = ttk.Button(control_frame, text="Connect", command=self.toggle_client)
        self.connect_button.grid(row=1, column=0, padx=5, pady=5)

        # Attack Frame
        attack_frame = ttk.LabelFrame(main_frame, text="Attack Tools", padding="10")
        attack_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=10)

        self.attack_button = ttk.Button(attack_frame, text="Launch DDoS Flood Attack", command=self.toggle_attack)
        self.attack_button.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.attack_button.config(state='normal')

        self.replay_attack_button = ttk.Button(attack_frame, text="Launch Replay Attack", command=self.toggle_replay_attack)
        self.replay_attack_button.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)

        # Log Frame
        log_frame = ttk.LabelFrame(main_frame, text="Client Logs", padding="10")
        log_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)

        self.log_display = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            state='disabled',
            height=15,
            width=80,
            bg="#1e1e1e",
            fg="white",
            insertbackground="white"
        )
        self.log_display.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.log_display.tag_config('info', foreground='blue')
        self.log_display.tag_config('error', foreground='red')
        self.log_display.tag_config('sent', foreground='orange')
        self.log_display.tag_config('recv', foreground='green')

        # Start background tasks
        self.root.after(100, self.process_log_queue)
        if not self.config:
            self.connect_button.config(state='disabled')

    def load_client_config(self):
        try:
            with open('configs/client.yaml', 'r') as f:
                return yaml.safe_load(f)
        except (FileNotFoundError, yaml.YAMLError) as e:
            self.log_message(f"ERROR: Could not load configs/client.yaml: {e}")
            return None

    def toggle_client(self):
        if self.client_process:
            self.stop_client()
        else:
            self.start_client()

    def start_client(self):
        if not self.config:
            self.log_message("ERROR: Client configuration is not loaded. Cannot connect.")
            return

        self.log_message(f"--- Connecting to {self.server_addr}... ---")
        self.connect_button.config(text="Disconnect")
        self.attack_button.config(state='disabled')

        command = [sys.executable, '-u', '-m', 'src.pytunnel.cli.client_cli', '--config', 'configs/client.yaml']
        full_command = command

        try:
            self.client_process = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
                preexec_fn=os.setsid
            )
        except Exception as e:
            self.log_message(f"ERROR starting client: {e}")
            self.stop_client()
            return

        threading.Thread(target=self.enqueue_output, args=(self.client_process.stdout, self.log_queue), daemon=True).start()
        threading.Thread(target=self.enqueue_output, args=(self.client_process.stderr, self.log_queue), daemon=True).start()

    def stop_client(self):
        if self.client_process:
            self.log_message("--- Disconnecting... ---")
            try:
                subprocess.run(['kill', '--', f'-{os.getpgid(self.client_process.pid)}'])
            except Exception as e:
                self.log_message(f"Error trying to kill process: {e}")
            self.client_process.wait()
        self.client_process = None
        self.connect_button.config(text="Connect")
        self.attack_button.config(state='normal')
        self.log_message("--- Client disconnected. ---")

    def toggle_attack(self):
        if self.attack_process:
            self.stop_attack()
        else:
            self.start_attack()

    def start_attack(self):
        if not self.config:
            self.log_message("ERROR: Client configuration is not loaded. Cannot start attack.")
            return

        ip = self.config['server_addr']
        port = self.config['server_port']

        self.log_message("--- Starting DDoS flood attack... ---")
        self.attack_button.config(text="Stop Attack")

        command = [sys.executable, 'tools/flood_attack.py', '--target', ip, '--port', str(port)]

        self.attack_process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        threading.Thread(target=self.enqueue_output, args=(self.attack_process.stdout, self.log_queue), daemon=True).start()
        threading.Thread(target=self.enqueue_output, args=(self.attack_process.stderr, self.log_queue), daemon=True).start()

    def stop_attack(self):
        if self.attack_process:
            self.log_message("--- Stopping DDoS attack... ---")
            self.attack_process.terminate()
            self.attack_process.wait()
        self.attack_process = None
        self.attack_button.config(text="Launch DDoS Flood Attack")

    def toggle_replay_attack(self):
        if self.replay_attack_process:
            self.stop_replay_attack()
        else:
            self.start_replay_attack()

    def start_replay_attack(self):
        if not self.config:
            self.log_message("ERROR: Client configuration is not loaded. Cannot start attack.")
            return

        ip = self.config['server_addr']
        port = self.config['server_port']

        self.log_message("--- Starting Replay attack... ---")
        self.replay_attack_button.config(text="Stop Replay Attack")

        command = [sys.executable, 'tools/replay_attack.py', '--target', ip, '--port', str(port)]

        self.replay_attack_process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        threading.Thread(target=self.enqueue_output, args=(self.replay_attack_process.stdout, self.log_queue), daemon=True).start()
        threading.Thread(target=self.enqueue_output, args=(self.replay_attack_process.stderr, self.log_queue), daemon=True).start()

    def stop_replay_attack(self):
        if self.replay_attack_process:
            self.log_message("--- Stopping Replay attack... ---")
            self.replay_attack_process.terminate()
            self.replay_attack_process.wait()
        self.replay_attack_process = None
        self.replay_attack_button.config(text="Launch Replay Attack")

    def enqueue_output(self, pipe, queue):
        try:
            for line in iter(pipe.readline, ''):
                queue.put(line)
        finally:
                pipe.close()

    def process_log_queue(self):
        while not self.log_queue.empty():
            line = self.log_queue.get_nowait()
            self.log_message(line.strip())
        self.root.after(100, self.process_log_queue)

    def log_message(self, message):
        print(message)
        self.log_display.config(state='normal')
        autoscroll = self.log_display.yview()[1] == 1.0

        # Determine color by content
        if "ERROR" in message:
            tag = 'error'
        elif "INFO" in message:
            tag = 'info'
        elif "SENT" in message:
            tag = 'sent'
        else:
            tag = 'recv'

        self.log_display.insert(tk.END, message + '\n', tag)

        if autoscroll:
            self.log_display.see(tk.END)
        self.log_display.config(state='disabled')

    def on_closing(self):
        self.stop_client()
        self.stop_attack()
        self.stop_replay_attack()
        self.root.destroy()

if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.stderr.write("This script must be run as root to create network interfaces.\n")
        sys.exit(1)

    root = tk.Tk()
    app = ClientUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
