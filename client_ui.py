#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext
import subprocess
import threading
import queue
import sys
import os

class ClientUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PyTunnel Client Control")
        self.client_process = None
        self.attack_process = None
        self.log_queue = queue.Queue()

        # --- UI Elements ---
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

        # Control Frame
        control_frame = ttk.LabelFrame(main_frame, text="Controls", padding="10")
        control_frame.grid(row=0, column=0, sticky=(tk.W, tk.E))
        control_frame.columnconfigure(1, weight=1)

        ttk.Label(control_frame, text="Server Address:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.server_addr_var = tk.StringVar(value="127.0.0.1:51820")
        self.server_addr_entry = ttk.Entry(control_frame, textvariable=self.server_addr_var, width=30)
        self.server_addr_entry.grid(row=0, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))

        self.connect_button = ttk.Button(control_frame, text="Connect", command=self.toggle_client)
        self.connect_button.grid(row=1, column=0, padx=5, pady=5)

        # Attack Frame
        attack_frame = ttk.LabelFrame(main_frame, text="Attack Tools", padding="10")
        attack_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=10)
        attack_frame.columnconfigure(0, weight=1)

        self.attack_button = ttk.Button(attack_frame, text="Launch DDoS Flood Attack", command=self.toggle_attack)
        self.attack_button.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.attack_button.config(state='disabled') # Disabled until connected

        # Log Frame
        log_frame = ttk.LabelFrame(main_frame, text="Client Logs", padding="10")
        log_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)

        self.log_display = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state='disabled', height=15, width=80)
        self.log_display.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # --- Start background tasks ---
        self.root.after(100, self.process_log_queue)

    def toggle_client(self):
        if self.client_process:
            self.stop_client()
        else:
            self.start_client()

    def start_client(self):
        server_addr = self.server_addr_var.get()
        if not server_addr:
            self.log_message("ERROR: Server address cannot be empty.")
            return

        self.log_message(f"--- Connecting to {server_addr}... ---")
        self.connect_button.config(text="Disconnect")
        self.server_addr_entry.config(state='disabled')
        self.attack_button.config(state='normal')

        command = [sys.executable, '-m', 'src.pytunnel.cli.client_cli', '--server', server_addr]
        full_command = ['sudo', '-E'] + command

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
                subprocess.run(['sudo', 'kill', '--', f'-{os.getpgid(self.client_process.pid)}'])
            except Exception as e:
                self.log_message(f"Error trying to kill process: {e}")
            self.client_process.wait()
        self.client_process = None
        self.connect_button.config(text="Connect")
        self.server_addr_entry.config(state='normal')
        self.attack_button.config(state='disabled')
        self.log_message("--- Client disconnected. ---")

    def toggle_attack(self):
        if self.attack_process:
            self.stop_attack()
        else:
            self.start_attack()

    def start_attack(self):
        server_addr = self.server_addr_var.get()
        try:
            ip, port_str = server_addr.split(':')
            port = int(port_str)
        except ValueError:
            self.log_message("ERROR: Invalid server address format for attack. Use IP:PORT.")
            return

        self.log_message("--- Starting DDoS flood attack... ---")
        self.attack_button.config(text="Stop Attack")

        command = [sys.executable, 'tools/flood_attack.py', '--target', ip, '--port', str(port)]
        
        # The attack script does not need sudo if scapy is installed correctly
        self.attack_process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        # We only log the output of the attack tool, not from the main client log
        attack_log_queue = queue.Queue()
        threading.Thread(target=self.enqueue_output, args=(self.attack_process.stdout, self.log_queue), daemon=True).start()
        threading.Thread(target=self.enqueue_output, args=(self.attack_process.stderr, self.log_queue), daemon=True).start()


    def stop_attack(self):
        if self.attack_process:
            self.log_message("--- Stopping DDoS attack... ---")
            self.attack_process.terminate()
            self.attack_process.wait()
        self.attack_process = None
        self.attack_button.config(text="Launch DDoS Flood Attack")

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
        self.log_display.config(state='normal')
        self.log_display.insert(tk.END, message + '\n')
        self.log_display.see(tk.END)
        self.log_display.config(state='disabled')

    def on_closing(self):
        self.stop_client()
        self.stop_attack()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
