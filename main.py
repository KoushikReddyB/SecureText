import tkinter as tk
from tkinter import ttk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import subprocess


after_id = None
footer_marquee_scroll_speed = 25  
footer_marquee_text = "Made by @KoushikReddyB"
def open_github(event):
    import webbrowser
    webbrowser.open("https://github.com/KoushikReddyB")

def start_marquee(event=None):  
    canvas.move(text_id, -1, 0)
    x1, _, x2, _ = canvas.bbox(text_id)
    if x2 < 0: 
        canvas.move(text_id, canvas.winfo_width(), 0)  
    global after_id
    after_id = canvas.after(footer_marquee_scroll_speed, start_marquee)  

def stop_marquee(event):
    canvas.after_cancel(after_id)

def switch_to_select_algorithm_page():
    # Hide current widgets
    title_label.place_forget()
    button_frame.place_forget()
    canvas.pack_forget()

    # Create Select Algorithm page
    select_algo_label = ttk.Label(window, text="Select Algorithm", font="Calibri 20 bold")
    select_algo_label.place(relx=0.5, rely=0.3, anchor="center")

    # Symmetric Encryption Algorithms
    symmetric_algorithms = [
        ("AES (Advanced Encryption Standard)", aes_function), 
        ("Blowfish", blowfish_function),
        ("DES (Data Encryption Standard)", des_function),
        ("Triple DES (3DES)", des3_function),
        ("ChaCha2.0", chacha_function)
    ]

    # Asymmetric Encryption Algorithms
    asymmetric_algorithms = [
        ("RSA (Rivest-Shamir-Adleman)", rsa_function),
        ("ECC (Elliptic Curve Cryptography)", ecc_function),
        ("Camellia", camellia_function),
        ("IDEA (International Data Encryption Algorithm)", idea_function)
    ]

    # Hashing Algorithms
    hashing_algorithms = [
        ("SHA-1 (Secure Hash Algorithm 1)", sha1_function),
        ("SHA-256 (Secure Hash Algorithm 256-bit)", sha256_function),
        ("SHA-512 (Secure Hash Algorithm 512-bit)", sha512_function),
        ("MD5 (Message Digest Algorithm 5)", md5_function)
    ]

    algo_options = [
        ("Symmetric Algorithms", symmetric_algorithms),
        ("Asymmetric Algorithms", asymmetric_algorithms),
        ("Hashing Algorithms", hashing_algorithms)
    ]

    selected_algo = tk.StringVar()
    algo_dropdown = ttk.Combobox(window, textvariable=selected_algo, values=[category[0] for category in algo_options], state="readonly")
    algo_dropdown.place(relx=0.5, rely=0.4, anchor="center")

    def on_category_select(event):
        selected_category = algo_dropdown.get()
        algo_dropdown['values'] = [algo[0] for category, algorithms in algo_options if category == selected_category for algo in algorithms]

    algo_dropdown.bind("<<ComboboxSelected>>", on_category_select)

    def submit_algorithm():
        selected_option = selected_algo.get()
        for category, algorithms in algo_options:
            for algo, function in algorithms:
                if algo == selected_option:
                    function()
                    return
        print("No function associated with selected algorithm.")

    submit_button = ttk.Button(window, text="Submit", command=submit_algorithm)
    submit_button.place(relx=0.5, rely=0.5, anchor="center")

    def go_back():
        # Clear the Select Algorithm page and show the main page again
        select_algo_label.place_forget()
        algo_dropdown.place_forget()
        submit_button.place_forget()
        back_button.place_forget()
        exit_button.grid(row=0, column=1, padx=20)  
        start_button.grid(row=0, column=0, padx=20)  
        title_label.place(relx=0.5, rely=0.4, anchor="center")
        button_frame.place(relx=0.5, rely=0.6, anchor="center")
        canvas.pack(side="bottom")

    back_button = ttk.Button(window, text="Back", command=go_back)
    back_button.place(relx=0.5, rely=0.6, anchor="center")
    window.geometry("800x450")
    
    # Marquee Text at the bottom of the window
    marquee_text = "SecureText: A GUI python application developed by KoushikReddyB"
    canvas_algo = tk.Canvas(window, width=800, height=20, bg="black", highlightthickness=0)
    canvas_algo.place(relx=0.5, rely=1.0, anchor="s")
    text_id_algo = canvas_algo.create_text(0, 10, anchor="w", text=marquee_text, fill="white", font="Calibri 10")

    def start_marquee_algo(event=None):
        canvas_algo.move(text_id_algo, -1, 0)
        x1, _, x2, _ = canvas_algo.bbox(text_id_algo)
        if x2 < 0: 
            canvas_algo.move(text_id_algo, canvas_algo.winfo_width(), 0)  
        global after_id
        after_id = canvas_algo.after(footer_marquee_scroll_speed, start_marquee_algo)  

    def stop_marquee_algo(event):
        canvas_algo.after_cancel(after_id)

    # Hover and Click Actions for Marquee on Select Algorithm Page
    canvas_algo.bind("<Enter>", stop_marquee_algo)
    canvas_algo.bind("<Leave>", start_marquee_algo) 

    # Start Marquee on Select Algorithm Page
    start_marquee_algo()

def exit_window():
    stop_marquee()  # Stop the marquee before closing the window
    window.destroy()

# Example function for each algorithm
def aes_function():
    print("You Selected AES Algorithm")
    subprocess.Popen(["python", "Algorithms/Symmentric Algorithms/aes_gui.py"])

def blowfish_function():
    print("You selected Blowfish algorithm.")
    subprocess.Popen(["python", "Algorithms/Symmentric Algorithms/blowfish_gui.py"])

def des_function():
    print("You selected DES algorithm.")
    subprocess.Popen(["python", "Algorithms/Symmentric Algorithms/des_gui.py"])

def des3_function():
    print("You selected 3DES algorithm.")
    subprocess.Popen(["python", "Algorithms/Symmentric Algorithms/3des_gui.py"])

def chacha_function():
    print("You selected ChaCha2.0 algorithm.")
    subprocess.Popen(["python", "Algorithms/Symmentric Algorithms/chacha20_gui.py"])

def rsa_function():
    print("You selected RSA algorithm.")
    subprocess.Popen(["python", "Algorithms/Asymmentric Algorithms/rsa_gui.py"])

def ecc_function():
    print("You selected ECC algorithm.")
    subprocess.Popen(["python", "Algorithms/Asymmentric Algorithms/ecc_gui.py"])

def camellia_function():
    print("You selected Camellia algorithm.")

def idea_function():
    print("You selected IDEA algorithm.")

def sha1_function():
    print("You selected SHA1 algorithm.")

def sha256_function():
    print("You selected SHA1 algorithm.")

def sha512_function():
    print("You selected SHA1 algorithm.")

def md5_function():
    print("You selected SHA1 algorithm.")

# Window 
window = tk.Tk()
window.title("SecureText: Developed by KoushikReddyB")
window.geometry("800x450") # going with 16:9 ratio

# Title
title_label = ttk.Label(master=window,
                        text="SecureText",
                        font="Calibri 43 bold")
title_label.place(relx=0.5, rely=0.4,
                  anchor="center") 
# for space between label and buttons

# Frame for buttons
button_frame = ttk.Frame(master=window)
button_frame.place(relx=0.5, rely=0.6,
                   anchor="center") 


# Exit Window Button
def exit_window():
  window.destroy()


# Creating buttons Start and Exit
start_button = ttk.Button(master=button_frame, text="Start", command=switch_to_select_algorithm_page)
exit_button = ttk.Button(master=button_frame, text="Exit", command=exit_window)
start_button.grid(row=0, column=0, padx=20)  
exit_button.grid(row=0, column=1, padx=20)

# Marquee Text
marquee_text = "SecureText: A GUI python application developed by KoushikReddyB"
canvas = tk.Canvas(window, width=800, height=20, bg="black", highlightthickness=0)
canvas.pack(side="bottom")

text_id = canvas.create_text(0, 10, anchor="w", text=marquee_text, fill="white", font="Calibri 10")

# Hover and Click Actions
canvas.bind("<Enter>", stop_marquee)
canvas.bind("<Leave>", start_marquee) 
canvas.bind("<Button-1>", open_github) 

# Start Marquee
start_marquee() 

# Stop the marquee when the window is closed
window.protocol("WM_DELETE_WINDOW", exit_window)

# Run
window.mainloop()
