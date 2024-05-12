import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import base64
import random


def _mul(x, y):
    assert 0 <= x <= 0xFFFF
    assert 0 <= y <= 0xFFFF

    if x == 0:
        x = 0x10000
    if y == 0:
        y = 0x10000

    r = (x * y) % 0x10001

    if r == 0x10000:
        r = 0

    assert 0 <= r <= 0xFFFF
    return r


def _KA_layer(x1, x2, x3, x4, round_keys):
    assert 0 <= x1 <= 0xFFFF
    assert 0 <= x2 <= 0xFFFF
    assert 0 <= x3 <= 0xFFFF
    assert 0 <= x4 <= 0xFFFF
    z1, z2, z3, z4 = round_keys[0:4]
    assert 0 <= z1 <= 0xFFFF
    assert 0 <= z2 <= 0xFFFF
    assert 0 <= z3 <= 0xFFFF
    assert 0 <= z4 <= 0xFFFF

    y1 = _mul(x1, z1)
    y2 = (x2 + z2) % 0x10000
    y3 = (x3 + z3) % 0x10000
    y4 = _mul(x4, z4)

    return y1, y2, y3, y4


def _MA_layer(y1, y2, y3, y4, round_keys):
    assert 0 <= y1 <= 0xFFFF
    assert 0 <= y2 <= 0xFFFF
    assert 0 <= y3 <= 0xFFFF
    assert 0 <= y4 <= 0xFFFF
    z5, z6 = round_keys[4:6]
    assert 0 <= z5 <= 0xFFFF
    assert 0 <= z6 <= 0xFFFF

    p = y1 ^ y3
    q = y2 ^ y4

    s = _mul(p, z5)
    t = _mul((q + s) % 0x10000, z6)
    u = (s + t) % 0x10000

    x1 = y1 ^ t
    x2 = y2 ^ u
    x3 = y3 ^ t
    x4 = y4 ^ u

    return x1, x2, x3, x4


class IDEA:
    def __init__(self, key):
        self._keys = None
        self.change_key(key)

    def change_key(self, key):
        assert 0 <= key < (1 << 128)
        modulus = 1 << 128

        sub_keys = []
        for i in range(9 * 6):
            sub_keys.append((key >> (112 - 16 * (i % 8))) % 0x10000)
            if i % 8 == 7:
                key = ((key << 25) | (key >> 103)) % modulus

        keys = []
        for i in range(9):
            round_keys = sub_keys[6 * i: 6 * (i + 1)]
            keys.append(tuple(round_keys))
        self._keys = tuple(keys)

    def encrypt(self, plaintext):
        assert 0 <= plaintext < (1 << 64)
        x1 = (plaintext >> 48) & 0xFFFF
        x2 = (plaintext >> 32) & 0xFFFF
        x3 = (plaintext >> 16) & 0xFFFF
        x4 = plaintext & 0xFFFF

        for i in range(8):
            round_keys = self._keys[i]

            y1, y2, y3, y4 = _KA_layer(x1, x2, x3, x4, round_keys)
            x1, x2, x3, x4 = _MA_layer(y1, y2, y3, y4, round_keys)

            x2, x3 = x3, x2

        # Note: The words x2 and x3 are not permuted in the last round
        # So here we use x1, x3, x2, x4 as input instead of x1, x2, x3, x4
        # in order to cancel the last permutation x2, x3 = x3, x2
        y1, y2, y3, y4 = _KA_layer(x1, x3, x2, x4, self._keys[8])

        ciphertext = (y1 << 48) | (y2 << 32) | (y3 << 16) | y4
        return ciphertext


class IDEAApp:
    def __init__(self, master):
        self.master = master
        self.master.title("IDEA Encryption/Decryption")
        self.master.geometry("800x450")

        self.create_widgets()

    def create_widgets(self):
        self.tab_control = ttk.Notebook(self.master)
        self.tab_control.pack(expand=1, fill="both")

        self.encryption_tab = ttk.Frame(self.tab_control)
        self.decryption_tab = ttk.Frame(self.tab_control)
        self.keygen_tab = ttk.Frame(self.tab_control)

        self.tab_control.add(self.encryption_tab, text="IDEA Encryption")
        self.tab_control.add(self.decryption_tab, text="IDEA Decryption")
        self.tab_control.add(self.keygen_tab, text="Key Generation")

        # IDEA Encryption Widgets
        self.plaintext_label = ttk.Label(self.encryption_tab, text="Plain Text:")
        self.plaintext_label.grid(row=0, column=0, sticky="w", padx=10, pady=5)

        self.plaintext_entry = tk.Text(self.encryption_tab, height=5, width=50)
        self.plaintext_entry.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

        self.key_label = ttk.Label(self.encryption_tab, text="Key (in hex):")
        self.key_label.grid(row=2, column=0, sticky="w", padx=10, pady=5)

        self.key_entry = ttk.Entry(self.encryption_tab, width=50)
        self.key_entry.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

        self.encrypt_button = ttk.Button(self.encryption_tab, text="Encrypt", command=self.encrypt)
        self.encrypt_button.grid(row=4, column=0, columnspan=2, pady=10)

        self.upload_key_button = ttk.Button(self.encryption_tab, text="Upload Key", command=self.upload_key)
        self.upload_key_button.grid(row=5, column=0, padx=10, pady=5)

        # IDEA Decryption Widgets
        self.ciphertext_label = ttk.Label(self.decryption_tab, text="Cipher Text:")
        self.ciphertext_label.grid(row=0, column=0, sticky="w", padx=10, pady=5)

        self.ciphertext_entry = tk.Text(self.decryption_tab, height=5, width=50)
        self.ciphertext_entry.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

        self.key_label_dec = ttk.Label(self.decryption_tab, text="Key (in hex):")
        self.key_label_dec.grid(row=2, column=0, sticky="w", padx=10, pady=5)

        self.key_entry_dec = ttk.Entry(self.decryption_tab, width=50)
        self.key_entry_dec.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

        self.decrypt_button = ttk.Button(self.decryption_tab, text="Decrypt", command=self.decrypt)
        self.decrypt_button.grid(row=4, column=0, columnspan=2, pady=10)

        self.upload_key_button_dec = ttk.Button(self.decryption_tab, text="Upload Key", command=self.upload_key_dec)
        self.upload_key_button_dec.grid(row=5, column=0, padx=10, pady=5)

        # Key Generation Widgets
        self.generate_key_button = ttk.Button(self.keygen_tab, text="Generate Key", command=self.generate_key)
        self.generate_key_button.grid(row=0, column=0, pady=10)

        self.download_key_button = ttk.Button(self.keygen_tab, text="Download Key", command=self.download_key)
        self.download_key_button.grid(row=1, column=0, pady=10)

        # Reset and Exit Buttons
        self.reset_button = ttk.Button(self.master, text="Reset", command=self.reset)
        self.reset_button.pack(side="left", padx=10, pady=10)

        self.exit_button = ttk.Button(self.master, text="Exit", command=self.master.quit)
        self.exit_button.pack(side="left", padx=10, pady=10)

    def generate_key(self):
        key = random.getrandbits(128)
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, hex(key)[2:].upper())

    def upload_key(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "r") as file:
                key = file.read().strip()
                self.key_entry.delete(0, tk.END)
                self.key_entry.insert(0, key)

    def upload_key_dec(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "r") as file:
                key = file.read().strip()
                self.key_entry_dec.delete(0, tk.END)
                self.key_entry_dec.insert(0, key)

    def encrypt(self):
        plaintext = self.plaintext_entry.get("1.0", tk.END).strip()
        key = self.key_entry.get().strip()

        if not plaintext:
            messagebox.showerror("Error", "Please enter plaintext.")
            return

        if not key:
            messagebox.showerror("Error", "Please enter a key.")
            return

        try:
            key = int(key, 16)
            my_IDEA = IDEA(key)
            encrypted = my_IDEA.encrypt(int(plaintext, 16))
            self.show_output(hex(encrypted))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        ciphertext = self.ciphertext_entry.get("1.0", tk.END).strip()
        key = self.key_entry_dec.get().strip()

        if not ciphertext:
            messagebox.showerror("Error", "Please enter ciphertext.")
            return

        if not key:
            messagebox.showerror("Error", "Please enter a key.")
            return

        try:
            key = int(key, 16)
            my_IDEA = IDEA(key)
            decrypted = my_IDEA.encrypt(int(ciphertext, 16))
            self.show_output(hex(decrypted))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_output(self, output_text):
        output_window = tk.Toplevel(self.master)
        output_window.title("Encryption/Decryption Output")
        output_label = ttk.Label(output_window, text="Output:")
        output_label.pack(pady=5)
        output_text_widget = tk.Text(output_window, height=5, width=50)
        output_text_widget.insert(tk.END, output_text)
        output_text_widget.pack(pady=5)

    def download_key(self):
        key = self.key_entry.get().strip()
        if key:
            filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if filename:
                with open(filename, "w") as file:
                    file.write(key)

    def reset(self):
        self.plaintext_entry.delete("1.0", tk.END)
        self.ciphertext_entry.delete("1.0", tk.END)
        self.key_entry.delete(0, tk.END)
        self.key_entry_dec.delete(0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = IDEAApp(root)
    root.mainloop()
