import tkinter as tk
from tkinter import ttk
import ttkbootstrap as tb

def caesar_cipher(text, shift, mode="encrypt"):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            if mode == "encrypt":
                result += chr((ord(char) - base + shift) % 26 + base)
            else:
                result += chr((ord(char) - base - shift) % 26 + base)
        else:
            result += char
    return result

def update_realtime(*args):
    text = entry_text.get()
    shift_val = shift_value.get()

    if not shift_val.isdigit():
        output_label.config(text="Shift must be a number.")
        return

    shift = int(shift_val)
    result = caesar_cipher(text, shift, "encrypt")
    output_label.config(text=result)

def try_all_shifts():
    window_all = tb.Toplevel(window)
    window_all.title("All Shifts")
    window_all.geometry("400x500")

    box = tk.Text(window_all, bg="#1b1b1b", fg="white", relief="flat")
    box.pack(fill="both", expand=True, padx=10, pady=10)

    text = entry_text.get()
    for s in range(26):
        decrypted = caesar_cipher(text, s, "decrypt")
        box.insert("end", f"Shift {s}: {decrypted}\n")

# ------------------------------------------------------------------

window = tb.Window(themename="darkly")
window.title("Caesar Cipher - New Gen UI")
window.geometry("540x420")

style = ttk.Style()
# Create modern flat entry style
style.configure(
    "FlatEntry.TEntry",
    padding=10,
    relief="flat",
    borderwidth=0,
    foreground="white",
)

# Title
title = tb.Label(window, text="🜁 Caesar Cipher (Live)", font=("Segoe UI", 18, "bold"))
title.pack(pady=15)

# Input Frame
frame = tb.Frame(window, padding=10)
frame.pack(fill="x", padx=20)

tb.Label(frame, text="Text", font=("Segoe UI", 11)).pack(anchor="w")

entry_text = tb.Entry(frame, style="FlatEntry.TEntry", font=("Segoe UI", 11))
entry_text.pack(fill="x", pady=5)

tb.Label(frame, text="Shift Value", font=("Segoe UI", 11)).pack(anchor="w")

shift_value = tk.StringVar()
shift_entry = tb.Entry(frame, textvariable=shift_value, style="FlatEntry.TEntry", width=10, font=("Segoe UI", 11))
shift_entry.pack(fill="x", pady=5)

shift_value.trace_add("write", update_realtime)
entry_text.bind("<KeyRelease>", update_realtime)

# Output
output_frame = tb.Frame(window)
output_frame.pack(fill="x", padx=20, pady=15)

tb.Label(output_frame, text="Output", font=("Segoe UI", 11)).pack(anchor="w")

output_label = tb.Label(output_frame, text="", wraplength=480, font=("Segoe UI", 12), foreground="white")
output_label.pack(fill="x", pady=5)

# Buttons
btn_frame = tb.Frame(window)
btn_frame.pack(pady=10)

all_btn = tb.Button(btn_frame, text="Try All Shifts", bootstyle="secondary", command=try_all_shifts)
all_btn.grid(row=0, column=0, padx=10)

reset_btn = tb.Button(btn_frame, text="Clear", bootstyle="danger", command=lambda: (entry_text.delete(0, "end"), output_label.config(text="")))
reset_btn.grid(row=0, column=1, padx=10)

window.mainloop()