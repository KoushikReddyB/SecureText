import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore
import os

class ChaChaApp:
    def __init__(self, master):
        self.master = master
        master.title("ChaCha2.0 Encryption/Decryption")

        self.plaintext_label = tk.Label(master, text="Plain Text / Cipher Text:")
        self.plaintext_label.grid(row=0, column=0, sticky="w")

        self.plaintext_entry = tk.Text(master, height=5, width=50)
        self.plaintext_entry.grid(row=1, column=0, columnspan=3, padx=10, pady=5)

        self.key_label = tk.Label(master, text="Key:")
        self.key_label.grid(row=2, column=0, sticky="w")

        self.key_entry = tk.Entry(master)
        self.key_entry.grid(row=2, column=1, padx=10, pady=5)

        self.nonce_label = tk.Label(master, text="Nonce:")
        self.nonce_label.grid(row=3, column=0, sticky="w")

        self.nonce_entry = tk.Entry(master)
        self.nonce_entry.grid(row=3, column=1, padx=10, pady=5)

        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt)
        self.encrypt_button.grid(row=4, column=0, padx=10, pady=5)

        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt)
        self.decrypt_button.grid(row=4, column=1, padx=10, pady=5)

        self.keygen_button = tk.Button(master, text="Generate Key", command=self.generate_key)
        self.keygen_button.grid(row=5, column=0, padx=10, pady=5)

        self.noncegen_button = tk.Button(master, text="Generate Nonce", command=self.generate_nonce)
        self.noncegen_button.grid(row=5, column=1, padx=10, pady=5)

        self.back_button = tk.Button(master, text="Reset", command=self.clear_text)
        self.back_button.grid(row=6, column=0, padx=10, pady=5)

        self.exit_button = tk.Button(master, text="Exit", command=master.quit)
        self.exit_button.grid(row=6, column=1, padx=10, pady=5)

    def generate_key(self):
        key = os.urandom(32)
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key.hex())

    def generate_nonce(self):
        nonce = os.urandom(12)
        self.nonce_entry.delete(0, tk.END)
        self.nonce_entry.insert(0, nonce.hex())

    def chacha_cipher(self, key, nonce):
        # ChaCha20 encryption
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
        return cipher

    def encrypt(self):
        plaintext = self.plaintext_entry.get("1.0", "end-1c")
        key = bytes.fromhex(self.key_entry.get())
        nonce = bytes.fromhex(self.nonce_entry.get())

        if not plaintext or not key or not nonce:
            messagebox.showerror("Error", "Please enter plaintext, key, and nonce.")
            return

        try:
            cipher = self.chacha_cipher(key, nonce)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
            messagebox.showinfo("Encrypted Text", ciphertext.hex())
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        ciphertext = bytes.fromhex(self.plaintext_entry.get("1.0", "end-1c"))
        key = bytes.fromhex(self.key_entry.get())
        nonce = bytes.fromhex(self.nonce_entry.get())

        if not ciphertext or not key or not nonce:
            messagebox.showerror("Error", "Please enter ciphertext, key, and nonce.")
            return

        try:
            cipher = self.chacha_cipher(key, nonce)
            decryptor = cipher.decryptor()
            decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
            messagebox.showinfo("Decrypted Text", decrypted_text.decode())
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def clear_text(self):
        self.plaintext_entry.delete("1.0", tk.END)
        self.key_entry.delete(0, tk.END)
        self.nonce_entry.delete(0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = ChaChaApp(root)
    root.mainloop()



# 045f20f36b21ba617f5d51b940a72b171a3373b99a41cb6c9a49c69543d702f7

# f19263eaa1f29e50e2afd02ac7de7a1c

# 3dd15324a2