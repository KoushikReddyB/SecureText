import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import base64

class DESApp:
    def __init__(self, master):
        self.master = master
        master.title("DES Encryption/Decryption")

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
        key = get_random_bytes(8)  # 8 bytes key for DES
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, base64.b64encode(key).decode())

    def encrypt(self):
        plaintext = self.plaintext_entry.get("1.0", "end-1c")
        mode = self.mode_var.get()
        key = self.key_entry.get()

        if not plaintext or not key:
            messagebox.showerror("Error", "Please enter plaintext and key.")
            return

        try:
            cipher_text = des_encrypt(plaintext, key, mode)
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
            decrypted_text = des_decrypt(ciphertext, key, mode)
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

def des_encrypt(plain_text, key, mode='ECB'):
    cipher = DES.new(base64.b64decode(key), DES.MODE_ECB if mode == 'ECB' else DES.MODE_CBC)
    # Padding the plaintext if its length is not a multiple of 8
    plain_text += ' ' * (8 - len(plain_text) % 8)
    cipher_text = cipher.encrypt(plain_text.encode())
    return base64.b64encode(cipher_text).decode()

def des_decrypt(cipher_text, key, mode='ECB'):
    cipher = DES.new(base64.b64decode(key), DES.MODE_ECB if mode == 'ECB' else DES.MODE_CBC)
    decrypted_text = cipher.decrypt(base64.b64decode(cipher_text))
    return decrypted_text.decode().rstrip()

if __name__ == "__main__":
    root = tk.Tk()
    app = DESApp(root)
    root.mainloop()
