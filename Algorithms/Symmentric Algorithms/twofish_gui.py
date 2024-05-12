import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from twofish import Twofish

class TwofishApp:
    def __init__(self, master):
        self.master = master
        master.title("Twofish Encryption/Decryption")

        self.plaintext_label = tk.Label(master, text="Plain Text / Cipher Text:")
        self.plaintext_label.grid(row=0, column=0, sticky="w")

        self.plaintext_entry = tk.Text(master, height=5, width=50)
        self.plaintext_entry.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

        self.key_label = tk.Label(master, text="Key:")
        self.key_label.grid(row=2, column=0, sticky="w")

        self.key_entry = tk.Entry(master)
        self.key_entry.grid(row=2, column=1, padx=10, pady=5)

        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt)
        self.encrypt_button.grid(row=3, column=0, padx=10, pady=5)

        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt)
        self.decrypt_button.grid(row=3, column=1, padx=10, pady=5)

        self.keygen_button = tk.Button(master, text="Key Generator", command=self.generate_key)
        self.keygen_button.grid(row=4, column=0, columnspan=2, padx=10, pady=5)

        self.back_button = tk.Button(master, text="Reset", command=self.clear_text)
        self.back_button.grid(row=5, column=0, padx=10, pady=5)

        self.exit_button = tk.Button(master, text="Exit", command=master.quit)
        self.exit_button.grid(row=5, column=1, padx=10, pady=5)

    def generate_key(self):
        key = os.urandom(32)  # Generate 32 bytes key for Twofish
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key.hex())

    def encrypt(self):
        plaintext = self.plaintext_entry.get("1.0", "end-1c").encode()
        key = bytes.fromhex(self.key_entry.get())

        if not plaintext or not key:
            messagebox.showerror("Error", "Please enter plaintext and key.")
            return

        try:
            ciphertext = encrypt_twofish(plaintext, key)
            self.show_output(ciphertext.hex(), "Encrypted Text")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        ciphertext = bytes.fromhex(self.plaintext_entry.get("1.0", "end-1c"))
        key = bytes.fromhex(self.key_entry.get())

        if not ciphertext or not key:
            messagebox.showerror("Error", "Please enter ciphertext and key.")
            return

        try:
            plaintext = decrypt_twofish(ciphertext, key)
            self.show_output(plaintext.decode(), "Decrypted Text")
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

def encrypt_twofish(plaintext, key):
    tf = Twofish(key)
    return tf.encrypt(plaintext)

def decrypt_twofish(ciphertext, key):
    tf = Twofish(key)
    return tf.decrypt(ciphertext)

if __name__ == "__main__":
    root = tk.Tk()
    app = TwofishApp(root)
    root.mainloop()
