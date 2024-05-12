import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.backends import default_backend # type: ignore
from cryptography.hazmat.primitives.asymmetric import rsa, padding # type: ignore
from cryptography.hazmat.primitives import serialization, hashes # type: ignore
import base64

class RSAApp:
    def __init__(self, master):
        self.master = master
        self.master.title("RSA Encryption/Decryption")
        self.master.geometry("800x450")

        self.create_widgets()

    def create_widgets(self):
        self.tab_control = ttk.Notebook(self.master)
        self.tab_control.pack(expand=1, fill="both")

        self.encryption_tab = ttk.Frame(self.tab_control)
        self.decryption_tab = ttk.Frame(self.tab_control)
        self.keygen_tab = ttk.Frame(self.tab_control)

        self.tab_control.add(self.encryption_tab, text="RSA Encryption")
        self.tab_control.add(self.decryption_tab, text="RSA Decryption")
        self.tab_control.add(self.keygen_tab, text="Key Generation")

        # RSA Encryption Widgets
        self.plaintext_label = ttk.Label(self.encryption_tab, text="Plain Text:")
        self.plaintext_label.grid(row=0, column=0, sticky="w", padx=10, pady=5)

        self.plaintext_entry = tk.Text(self.encryption_tab, height=5, width=50)
        self.plaintext_entry.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

        self.public_key_label = ttk.Label(self.encryption_tab, text="Public Key:")
        self.public_key_label.grid(row=2, column=0, sticky="w", padx=10, pady=5)

        self.public_key_entry = tk.Text(self.encryption_tab, height=3, width=50)
        self.public_key_entry.grid(row=3, column=0, padx=10, pady=5)

        self.upload_public_key_button = ttk.Button(self.encryption_tab, text="Upload", command=self.upload_public_key)
        self.upload_public_key_button.grid(row=3, column=1, padx=10, pady=5)

        self.encrypt_button = ttk.Button(self.encryption_tab, text="Encrypt", command=self.encrypt)
        self.encrypt_button.grid(row=4, column=0, columnspan=2, pady=10)

        # RSA Decryption Widgets
        self.ciphertext_label = ttk.Label(self.decryption_tab, text="Cipher Text:")
        self.ciphertext_label.grid(row=0, column=0, sticky="w", padx=10, pady=5)

        self.ciphertext_entry = tk.Text(self.decryption_tab, height=5, width=50)
        self.ciphertext_entry.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

        self.private_key_label = ttk.Label(self.decryption_tab, text="Private Key:")
        self.private_key_label.grid(row=2, column=0, sticky="w", padx=10, pady=5)

        self.private_key_entry = tk.Text(self.decryption_tab, height=3, width=50)
        self.private_key_entry.grid(row=3, column=0, padx=10, pady=5)

        self.upload_private_key_button = ttk.Button(self.decryption_tab, text="Upload", command=self.upload_private_key)
        self.upload_private_key_button.grid(row=3, column=1, padx=10, pady=5)

        self.decrypt_button = ttk.Button(self.decryption_tab, text="Decrypt", command=self.decrypt)
        self.decrypt_button.grid(row=4, column=0, columnspan=2, pady=10)

        # Key Generation Widgets
        self.key_size_label = ttk.Label(self.keygen_tab, text="Key Size:")
        self.key_size_label.grid(row=0, column=0, sticky="w", padx=10, pady=5)

        self.key_size_var = tk.StringVar()
        self.key_size_dropdown = ttk.Combobox(self.keygen_tab, textvariable=self.key_size_var, values=["512", "1024", "2048", "3072", "4096"])
        self.key_size_dropdown.grid(row=0, column=1, padx=10, pady=5)

        self.generate_key_button = ttk.Button(self.keygen_tab, text="Generate Key", command=self.generate_key)
        self.generate_key_button.grid(row=1, column=0, columnspan=2, pady=10)

        self.download_public_key_button = ttk.Button(self.keygen_tab, text="Download Public Key", command=self.download_public_key)
        self.download_public_key_button.grid(row=2, column=0, padx=10, pady=5)

        self.download_private_key_button = ttk.Button(self.keygen_tab, text="Download Private Key", command=self.download_private_key)
        self.download_private_key_button.grid(row=2, column=1, padx=10, pady=5)

        # Reset and Exit Buttons
        self.reset_button = ttk.Button(self.master, text="Reset", command=self.reset)
        self.reset_button.pack(side="left", padx=10, pady=10)

        self.exit_button = ttk.Button(self.master, text="Exit", command=self.master.quit)
        self.exit_button.pack(side="left", padx=10, pady=10)

    def upload_public_key(self):
        file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if file_path:
            with open(file_path, "rb") as file:
                public_key_pem = file.read()
                self.public_key_entry.delete("1.0", tk.END)
                self.public_key_entry.insert("1.0", public_key_pem.decode())

    def upload_private_key(self):
        file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if file_path:
            with open(file_path, "rb") as file:
                private_key_pem = file.read()
                self.private_key_entry.delete("1.0", tk.END)
                self.private_key_entry.insert("1.0", private_key_pem.decode())

    def encrypt(self):
        plaintext = self.plaintext_entry.get("1.0", tk.END)
        public_key_pem = self.public_key_entry.get("1.0", tk.END)

        if not plaintext.strip() or not public_key_pem.strip():
            messagebox.showerror("Error", "Please enter plaintext and public key.")
            return

        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
            ciphertext = public_key.encrypt(plaintext.encode(), padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
            output_window = tk.Toplevel(self.master)
            output_window.title("Encryption Output")
            output_text = tk.Text(output_window, height=5, width=50)
            output_text.insert(tk.END, base64.b64encode(ciphertext).decode())
            output_text.pack()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        ciphertext = self.ciphertext_entry.get("1.0", tk.END)
        private_key_pem = self.private_key_entry.get("1.0", tk.END)

        if not ciphertext.strip() or not private_key_pem.strip():
            messagebox.showerror("Error", "Please enter ciphertext and private key.")
            return

        try:
            private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
            plaintext = private_key.decrypt(
                base64.b64decode(ciphertext.encode()),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            output_window = tk.Toplevel(self.master)
            output_window.title("Decryption Output")
            output_text = tk.Text(output_window, height=5, width=50)
            output_text.insert(tk.END, plaintext.decode())
            output_text.pack()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def generate_key(self):
        key_size = int(self.key_size_var.get())
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
        public_key = private_key.public_key()
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.private_key_entry.delete("1.0", tk.END)
        self.private_key_entry.insert("1.0", private_key_pem.decode())
        self.public_key_entry.delete("1.0", tk.END)
        self.public_key_entry.insert("1.0", public_key_pem.decode())

    def download_public_key(self):
        public_key_pem = self.public_key_entry.get("1.0", tk.END).strip()
        if public_key_pem:
            filename = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
            if filename:
                with open(filename, "wb") as file:
                    file.write(public_key_pem.encode())

    def download_private_key(self):
        private_key_pem = self.private_key_entry.get("1.0", tk.END).strip()
        if private_key_pem:
            filename = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
            if filename:
                with open(filename, "wb") as file:
                    file.write(private_key_pem.encode())

    def reset(self):
        self.plaintext_entry.delete("1.0", tk.END)
        self.public_key_entry.delete("1.0", tk.END)
        self.private_key_entry.delete("1.0", tk.END)
        self.ciphertext_entry.delete("1.0", tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = RSAApp(root)
    root.mainloop()