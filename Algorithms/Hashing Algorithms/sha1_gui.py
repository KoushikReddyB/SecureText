import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import hashlib
import time

class VerificationWindow(tk.Toplevel):
    def __init__(self, master, result, color):
        super().__init__(master)
        self.title("Verification Result")
        self.result_label = tk.Label(self, text=result, fg=color, font=("Arial", 18, "bold"))
        self.result_label.pack()
        self.timer_label = tk.Label(self, text="Closing the window in 3 seconds", font=("Arial", 12))
        self.timer_label.pack()
        self.remaining_time = 3
        self.update_timer()

    def update_timer(self):
        if self.remaining_time >= 0:
            self.timer_label.config(text=f"Closing the window in {self.remaining_time} seconds")
            self.remaining_time -= 1
            self.after(1000, self.update_timer)
        else:
            self.destroy()

class SHA1App:
    def __init__(self, master):
        self.master = master
        master.title("SHA-1 Hashing")

        # Tabs
        self.tabs = ttk.Notebook(master)
        self.tabs.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

        # Generate Hash Tab
        self.generate_tab = ttk.Frame(self.tabs)
        self.tabs.add(self.generate_tab, text="Generate Hash")
        self.generate_hash_tab()

        # Verify Hash Tab
        self.verify_tab = ttk.Frame(self.tabs)
        self.tabs.add(self.verify_tab, text="Verify Hash")
        self.verify_hash_tab()

    def generate_hash_tab(self):
        self.generate_text_label = tk.Label(self.generate_tab, text="Plain Text:")
        self.generate_text_label.grid(row=0, column=0, sticky="w")

        self.generate_text_entry = tk.Text(self.generate_tab, height=5, width=50)
        self.generate_text_entry.grid(row=1, column=0, padx=10, pady=5)

        self.generate_button = tk.Button(self.generate_tab, text="Generate", command=self.generate_hash)
        self.generate_button.grid(row=2, column=0, padx=10, pady=5)

        self.result_label = tk.Label(self.generate_tab, text="Result:")
        self.result_label.grid(row=3, column=0, sticky="w")

        self.result_text = tk.Text(self.generate_tab, height=5, width=50)
        self.result_text.grid(row=4, column=0, padx=10, pady=5)

        self.reset_button = tk.Button(self.generate_tab, text="Reset", command=self.reset_generate_tab)
        self.reset_button.grid(row=5, column=0, padx=10, pady=5)

        self.exit_button = tk.Button(self.generate_tab, text="Exit", command=self.master.destroy)
        self.exit_button.grid(row=5, column=1, padx=10, pady=5)

    def verify_hash_tab(self):
        self.hash_label = tk.Label(self.verify_tab, text="Hash:")
        self.hash_label.grid(row=0, column=0, sticky="w")

        self.hash_entry = tk.Text(self.verify_tab, height=5, width=50)
        self.hash_entry.grid(row=1, column=0, padx=10, pady=5)

        self.verify_text_label = tk.Label(self.verify_tab, text="Message to Verify:")
        self.verify_text_label.grid(row=2, column=0, sticky="w")

        self.verify_text_entry = tk.Text(self.verify_tab, height=5, width=50)
        self.verify_text_entry.grid(row=3, column=0, padx=10, pady=5)

        self.verify_button = tk.Button(self.verify_tab, text="Verify", command=self.verify_hash)
        self.verify_button.grid(row=4, column=0, padx=10, pady=5)

        self.reset_button = tk.Button(self.verify_tab, text="Reset", command=self.reset_verify_tab)
        self.reset_button.grid(row=5, column=0, padx=10, pady=5)

        self.exit_button = tk.Button(self.verify_tab, text="Exit", command=self.master.destroy)
        self.exit_button.grid(row=5, column=1, padx=10, pady=5)

    def generate_hash(self):
        plaintext = self.generate_text_entry.get("1.0", "end-1c")
        if not plaintext:
            messagebox.showerror("Error", "Please enter text to generate hash.")
            return

        sha1_hash = hashlib.sha1(plaintext.encode()).hexdigest()
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, sha1_hash)

    def verify_hash(self):
        message = self.verify_text_entry.get("1.0", "end-1c")
        hash_to_verify = self.hash_entry.get("1.0", "end-1c")

        if not message or not hash_to_verify:
            messagebox.showerror("Error", "Please enter both hash and message to verify.")
            return

        calculated_hash = hashlib.sha1(message.encode()).hexdigest()

        if calculated_hash == hash_to_verify.strip():
            self.show_verification_result("Success", "green")
        else:
            self.show_verification_result("Failed", "red")

    def show_verification_result(self, result, color):
        verification_window = VerificationWindow(self.master, result, color)

    def reset_generate_tab(self):
        self.generate_text_entry.delete("1.0", tk.END)
        self.result_text.delete("1.0", tk.END)

    def reset_verify_tab(self):
        self.hash_entry.delete("1.0", tk.END)
        self.verify_text_entry.delete("1.0", tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = SHA1App(root)
    root.mainloop()
