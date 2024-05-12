import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

class AESApp:
    def __init__(self, master):
        self.master = master
        master.title("AES Encryption/Decryption")

        self.plaintext_label = tk.Label(master, text="Plain Text / Cipher Text:")
        self.plaintext_label.grid(row=0, column=0, sticky="w")

        self.plaintext_entry = tk.Text(master, height=5, width=50)
        self.plaintext_entry.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

        self.mode_label = tk.Label(master, text="Mode:")
        self.mode_label.grid(row=2, column=0, sticky="w")

        self.mode_var = tk.StringVar()
        self.mode_var.set("ECB")
        self.mode_dropdown = ttk.Combobox(master, textvariable=self.mode_var, values=["ECB", "CBC"])
        self.mode_dropdown.grid(row=2, column=1, padx=10, pady=5)

        self.key_label = tk.Label(master, text="Key:")
        self.key_label.grid(row=3, column=0, sticky="w")

        self.key_entry = tk.Entry(master)
        self.key_entry.grid(row=3, column=1, padx=10, pady=5)

        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt)
        self.encrypt_button.grid(row=4, column=0, padx=10, pady=5)

        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt)
        self.decrypt_button.grid(row=4, column=1, padx=10, pady=5)

        self.keygen_button = tk.Button(master, text="Key Generator", command=self.generate_key)
        self.keygen_button.grid(row=5, column=0, columnspan=2, padx=10, pady=5)

        self.back_button = tk.Button(master, text="Reset", command=self.clear_text)
        self.back_button.grid(row=6, column=0, padx=10, pady=5)

        self.exit_button = tk.Button(master, text="Exit", command=master.quit)
        self.exit_button.grid(row=6, column=1, padx=10, pady=5)

    def generate_key(self):
        key = get_random_bytes(16)  # 16 bytes key for AES-128
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key.hex())

    def encrypt(self):
        plaintext = self.plaintext_entry.get("1.0", "end-1c")
        mode = self.mode_var.get()
        key = self.key_entry.get()

        if not plaintext or not key:
            messagebox.showerror("Error", "Please enter plaintext and key.")
            return

        try:
            cipher_text = aes_encrypt(plaintext, key, mode)
            self.show_output(cipher_text, "Encrypted Text")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        ciphertext = self.plaintext_entry.get("1.0", "end-1c")
        mode = self.mode_var.get()
        key = self.key_entry.get()

        if not ciphertext or not key:
            messagebox.showerror("Error", "Please enter ciphertext and key.")
            return

        try:
            decrypted_text = aes_decrypt(ciphertext, key, mode)
            self.show_output(decrypted_text, "Decrypted Text")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_output(self, text, title):
        output_window = tk.Toplevel(self.master)
        output_window.title(title)
        output_label = tk.Label(output_window, text=text)
        output_label.pack()

    def clear_text(self):
        self.plaintext_entry.delete("1.0", tk.END)
        self.key_entry.delete(0, tk.END)

def generate_key():
    key = get_random_bytes(16)  # 16 bytes key for AES-128
    messagebox.showinfo("Generated Key", key.hex())

def aes_encrypt(plaintext, key, mode='ECB'):
    cipher = AES.new(key.encode(), AES.MODE_ECB if mode == 'ECB' else AES.MODE_CBC)
    plaintext = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(plaintext)
    return base64.b64encode(ciphertext).decode()

def aes_decrypt(ciphertext, key, mode='ECB'):
    cipher = AES.new(key.encode(), AES.MODE_ECB if mode == 'ECB' else AES.MODE_CBC)
    ciphertext = base64.b64decode(ciphertext)
    decrypted_text = cipher.decrypt(ciphertext)
    return unpad(decrypted_text, AES.block_size).decode()

if __name__ == "__main__":
    root = tk.Tk()
    app = AESApp(root)
    root.mainloop()