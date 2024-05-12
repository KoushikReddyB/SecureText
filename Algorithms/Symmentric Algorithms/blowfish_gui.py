import tkinter as tk
from tkinter import messagebox
from tkinter import scrolledtext
from tkinter import ttk
from Crypto.Cipher import Blowfish
from Crypto import Random
import base64
import os

class BlowfishGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Blowfish Encryption/Decryption")
        self.root.geometry("600x400")

        self.plaintext = tk.StringVar()
        self.key = tk.StringVar()
        self.mode = tk.StringVar(value="ECB")

        self.create_widgets()

    def create_widgets(self):
        self.text_field = scrolledtext.ScrolledText(self.root, width=60, height=10)
        self.text_field.grid(row=0, column=0, columnspan=3, padx=10, pady=10)

        mode_label = tk.Label(self.root, text="Mode:")
        mode_label.grid(row=1, column=0, padx=10, pady=5)
        mode_dropdown = ttk.Combobox(self.root, textvariable=self.mode, values=["ECB", "CBC", "CFB", "OFB"])
        mode_dropdown.grid(row=1, column=1, padx=10, pady=5)

        key_label = tk.Label(self.root, text="Key:")
        key_label.grid(row=2, column=0, padx=10, pady=5)
        self.key_entry = tk.Entry(self.root, textvariable=self.key)
        self.key_entry.grid(row=2, column=1, padx=10, pady=5)

        encrypt_button = tk.Button(self.root, text="Encrypt", command=self.encrypt)
        encrypt_button.grid(row=3, column=0, padx=10, pady=5)
        decrypt_button = tk.Button(self.root, text="Decrypt", command=self.decrypt)
        decrypt_button.grid(row=3, column=1, padx=10, pady=5)
        keygen_button = tk.Button(self.root, text="Key Generator", command=self.generate_key)
        keygen_button.grid(row=3, column=2, padx=10, pady=5)

        exit_button = tk.Button(self.root, text="Exit", command=self.root.quit)
        exit_button.grid(row=4, column=0, padx=10, pady=5)

    def generate_key(self):
        key = generate_key()
        key_window = tk.Toplevel(self.root)
        key_window.title("Generated Key")
        key_window.geometry("300x100")
        key_label = tk.Label(key_window, text="Generated Key: " + key.hex())
        key_label.pack(pady=10)

    def encrypt(self):
        try:
            key = self.key.get().encode()
            mode = self.mode.get()
            plain_text = self.text_field.get("1.0", tk.END).strip().encode()

            cipher = Blowfish.new(key, getattr(Blowfish, "MODE_" + mode))
            encrypted_text = cipher.encrypt(plain_text)
            self.show_output(encrypted_text.decode())
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        try:
            key = self.key.get().encode()
            mode = self.mode.get()
            cipher_text = self.text_field.get("1.0", tk.END).strip().encode()

            cipher = Blowfish.new(key, getattr(Blowfish, "MODE_" + mode))
            decrypted_text = cipher.decrypt(cipher_text)
            self.show_output(decrypted_text.decode().rstrip('\0'))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_output(self, output):
        output_window = tk.Toplevel(self.root)
        output_window.title("Output")
        output_window.geometry("400x200")
        output_label = tk.Label(output_window, text=output)
        output_label.pack(pady=10)

def generate_key():
    return os.urandom(16)

if __name__ == "__main__":
    root = tk.Tk()
    app = BlowfishGUI(root)
    root.mainloop()
