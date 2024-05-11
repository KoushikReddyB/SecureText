import tkinter as tk
from tkinter import ttk

after_id = None  
footer_marquee_scroll_speed = 25  # Speed of scrolling in milliseconds

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
start_button = ttk.Button(master=button_frame, text="Start")
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

# Run
window.mainloop()