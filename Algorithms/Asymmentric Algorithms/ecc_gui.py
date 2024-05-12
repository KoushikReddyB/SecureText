import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

class ECCApp:
    def __init__(self, master):
        self.master = master
        self.master.title("ECC Encryption/Decryption")
        self.master.geometry("800x450")

        self.create_widgets()

    def create_widgets(self):
        self.tab_control = ttk.Notebook(self.master)
        self.tab_control.pack(expand=1, fill="both")

        self.encryption_tab = ttk.Frame(self.tab_control)
        self.decryption_tab = ttk.Frame(self.tab_control)
        self.keygen_tab = ttk.Frame(self.tab_control)

        self.tab_control.add(self.encryption_tab, text="ECC Encryption")
        self.tab_control.add(self.decryption_tab, text="ECC Decryption")
        self.tab_control.add(self.keygen_tab, text="Key Generation")

        # ECC Encryption Widgets
        self.plaintext_label_enc = ttk.Label(self.encryption_tab, text="Plain Text:")
        self.plaintext_label_enc.grid(row=0, column=0, sticky="w", padx=10, pady=5)

        self.plaintext_entry_enc = tk.Text(self.encryption_tab, height=5, width=50)
        self.plaintext_entry_enc.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

        self.public_key_label_enc = ttk.Label(self.encryption_tab, text="Public Key A:")
        self.public_key_label_enc.grid(row=2, column=0, sticky="w", padx=10, pady=5)

        self.public_key_entry_enc = tk.Text(self.encryption_tab, height=3, width=50)
        self.public_key_entry_enc.grid(row=3, column=0, padx=10, pady=5)

        self.upload_public_key_button_enc = ttk.Button(self.encryption_tab, text="Upload", command=self.upload_public_key_enc)
        self.upload_public_key_button_enc.grid(row=3, column=1, padx=10, pady=5)

        self.encrypt_button = ttk.Button(self.encryption_tab, text="Encrypt", command=self.encrypt)
        self.encrypt_button.grid(row=4, column=0, columnspan=2, pady=10)

        # ECC Decryption Widgets
        self.ciphertext_label_dec = ttk.Label(self.decryption_tab, text="Cipher Text:")
        self.ciphertext_label_dec.grid(row=0, column=0, sticky="w", padx=10, pady=5)

        self.ciphertext_entry_dec = tk.Text(self.decryption_tab, height=5, width=50)
        self.ciphertext_entry_dec.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

        self.private_key_label_dec = ttk.Label(self.decryption_tab, text="Private Key B:")
        self.private_key_label_dec.grid(row=2, column=0, sticky="w", padx=10, pady=5)

        self.private_key_entry_dec = tk.Text(self.decryption_tab, height=3, width=50)
        self.private_key_entry_dec.grid(row=3, column=0, padx=10, pady=5)

        self.upload_private_key_button_dec = ttk.Button(self.decryption_tab, text="Upload", command=self.upload_private_key_dec)
        self.upload_private_key_button_dec.grid(row=3, column=1, padx=10, pady=5)

        self.decrypt_button = ttk.Button(self.decryption_tab, text="Decrypt", command=self.decrypt)
        self.decrypt_button.grid(row=4, column=0, columnspan=2, pady=10)

        # Key Generation Widgets
        self.key_size_label_keygen = ttk.Label(self.keygen_tab, text="Key Size:")
        self.key_size_label_keygen.grid(row=0, column=0, sticky="w", padx=10, pady=5)

        self.key_size_var_keygen = tk.StringVar()
        self.key_size_dropdown_keygen = ttk.Combobox(self.keygen_tab, textvariable=self.key_size_var_keygen, values=["192", "224", "256"])
        self.key_size_dropdown_keygen.grid(row=0, column=1, padx=10, pady=5)

        self.generate_key_button_keygen = ttk.Button(self.keygen_tab, text="Generate Key", command=self.generate_key)
        self.generate_key_button_keygen.grid(row=1, column=0, columnspan=2, pady=10)

        self.download_public_key_button_keygen = ttk.Button(self.keygen_tab, text="Download Public Key", command=self.download_public_key)
        self.download_public_key_button_keygen.grid(row=2, column=0, padx=10, pady=5)

        self.download_private_key_button_keygen = ttk.Button(self.keygen_tab, text="Download Private Key", command=self.download_private_key)
        self.download_private_key_button_keygen.grid(row=2, column=1, padx=10, pady=5)

        # Reset and Exit Buttons
        self.reset_button = ttk.Button(self.master, text="Reset", command=self.reset)
        self.reset_button.pack(side="left", padx=10, pady=10)

        self.exit_button = ttk.Button(self.master, text="Exit", command=self.master.quit)
        self.exit_button.pack(side="left", padx=10, pady=10)

    def upload_public_key_enc(self):
        file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if file_path:
            with open(file_path, "rb") as file:
                public_key_pem = file.read()
                self.public_key_entry_enc.delete("1.0", tk.END)
                self.public_key_entry_enc.insert("1.0", public_key_pem.decode())

    def upload_private_key_dec(self):
        file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if file_path:
            with open(file_path, "rb") as file:
                private_key_pem = file.read()
                self.private_key_entry_dec.delete("1.0", tk.END)
                self.private_key_entry_dec.insert("1.0", private_key_pem.decode())

    def encrypt(self):
        plaintext = self.plaintext_entry_enc.get("1.0", tk.END)
        public_key_pem = self.public_key_entry_enc.get("1.0", tk.END)

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
        ciphertext = self.ciphertext_entry_dec.get("1.0", tk.END)
        private_key_pem = self.private_key_entry_dec.get("1.0", tk.END)

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
        key_size = int(self.key_size_var_keygen.get())
        private_key_a = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
        public_key_a = private_key_a.public_key()
        private_key_b = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
        public_key_b = private_key_b.public_key()

        private_key_a_pem = private_key_a.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_a_pem = public_key_a.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        private_key_b_pem = private_key_b.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_b_pem = public_key_b.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.public_key_entry_enc.delete("1.0", tk.END)
        self.public_key_entry_enc.insert("1.0", public_key_a_pem.decode())

        self.private_key_entry_dec.delete("1.0", tk.END)
        self.private_key_entry_dec.insert("1.0", private_key_b_pem.decode())

        messagebox.showinfo("Keys Generated", "Keys have been generated successfully!")

    def download_public_key(self):
        public_key_pem = self.public_key_entry_enc.get("1.0", tk.END).strip()
        if public_key_pem:
            filename = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
            if filename:
                with open(filename, "wb") as file:
                    file.write(public_key_pem.encode())

    def download_private_key(self):
        private_key_pem = self.private_key_entry_dec.get("1.0", tk.END).strip()
        if private_key_pem:
            filename = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
            if filename:
                with open(filename, "wb") as file:
                    file.write(private_key_pem.encode())

    def reset(self):
        self.plaintext_entry_enc.delete("1.0", tk.END)
        self.public_key_entry_enc.delete("1.0", tk.END)
        self.ciphertext_entry_dec.delete("1.0", tk.END)
        self.private_key_entry_dec.delete("1.0", tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = ECCApp(root)
    root.mainloop()
