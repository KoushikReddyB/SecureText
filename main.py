import tkinter as tk
from tkinter import ttk

# Window 
window = tk.Tk()
window.title("SecureText: Developed by KoushikReddyB")
window.geometry("800x450") # going with 16:9 ratio

# Title
title_lable = ttk.Label(master= window, text="SecureText", font= "Calibri 35 bold")
title_lable.pack()

# Run
window.mainloop()