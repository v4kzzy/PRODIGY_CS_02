import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox  # FIXED: changed message_box to messagebox
from PIL import Image
import os

def get_key_from_text(text_key):
    """
    Converts a text string (like "labubu") into a usable number (0-255).
    """
    if not text_key:
        return 0
    total = sum(ord(char) for char in text_key)
    return total % 256

def process_image(action):
    # 1. Get the file path
    filepath = entry_file.get()
    text_key = entry_key.get()

    if not filepath:
        messagebox.showerror("Error", "Please select an image first!") # FIXED
        return
    if not text_key:
        messagebox.showerror("Error", "Please enter a Secret Key name!") # FIXED
        return

    # 2. Convert text key to number
    numeric_key = get_key_from_text(text_key)

    try:
        # 3. Open and Process Image
        img = Image.open(filepath)
        img = img.convert("RGB")
        pixels = img.load()
        width, height = img.size

        for x in range(width):
            for y in range(height):
                r, g, b = pixels[x, y]

                # XOR Operation
                r_enc = r ^ numeric_key
                g_enc = g ^ numeric_key
                b_enc = b ^ numeric_key

                # Swap Channels
                pixels[x, y] = (b_enc, g_enc, r_enc)

        # 4. Save File
        directory = os.path.dirname(filepath)
        filename = os.path.basename(filepath)
        
        if action == "encrypt":
            save_path = os.path.join(directory, f"encrypted_{filename}")
            success_msg = "Image Encrypted!"
        else:
            save_path = os.path.join(directory, f"decrypted_{filename}")
            success_msg = "Image Decrypted!"

        img.save(save_path)
        lbl_status.config(text=f"Saved: {os.path.basename(save_path)}", bootstyle="success")
        messagebox.showinfo("Success", f"{success_msg}\nSaved as: {os.path.basename(save_path)}") # FIXED

    except Exception as e:
        messagebox.showerror("Error", f"Something went wrong:\n{e}") # FIXED

def browse_file():
    filename = filedialog.askopenfilename(filetypes=[("Images", "*.jpg;*.jpeg;*.png;*.bmp")])
    entry_file.delete(0, END)
    entry_file.insert(0, filename)

# --- GUI SETUP ---
app = tb.Window(themename="cyborg")
app.title("Image Encryptor")
app.geometry("500x350")

# Title
lbl_title = tb.Label(app, text="Image Encryption Tool", font=("Helvetica", 18, "bold"), bootstyle="info")
lbl_title.pack(pady=20)

# File Selection
frame_file = tb.Frame(app)
frame_file.pack(pady=10, padx=20, fill=X)
entry_file = tb.Entry(frame_file)
entry_file.pack(side=LEFT, fill=X, expand=YES, padx=(0, 10))
btn_browse = tb.Button(frame_file, text="Browse", command=browse_file, bootstyle="outline")
btn_browse.pack(side=RIGHT)

# Key Input
frame_key = tb.Frame(app)
frame_key.pack(pady=10, padx=20, fill=X)
lbl_key = tb.Label(frame_key, text="Secret Name (Key):")
lbl_key.pack(side=LEFT, padx=(0, 10))
entry_key = tb.Entry(frame_key)
entry_key.insert(0, "labubu")
entry_key.pack(side=LEFT, fill=X, expand=YES)

# Action Buttons
frame_btns = tb.Frame(app)
frame_btns.pack(pady=20)
btn_encrypt = tb.Button(frame_btns, text="Encrypt", bootstyle="danger", command=lambda: process_image("encrypt"))
btn_encrypt.pack(side=LEFT, padx=10)
btn_decrypt = tb.Button(frame_btns, text="Decrypt", bootstyle="success", command=lambda: process_image("decrypt"))
btn_decrypt.pack(side=LEFT, padx=10)

# Status
lbl_status = tb.Label(app, text="Ready...", bootstyle="secondary")
lbl_status.pack(side=BOTTOM, pady=10)

app.mainloop()