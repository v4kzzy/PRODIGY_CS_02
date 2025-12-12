import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import os
import threading
import time

class ImageEncryptorApp(tb.Window):
    def __init__(self):
        super().__init__(themename="cyborg")
        self.title("PixelCipher Pro")
        self.geometry("600x750")
        
        # State variables
        self.selected_file_path = None
        
        # --- UI CONSTRUCTION ---
        self.create_header()
        self.create_source_section()
        self.create_security_section()
        self.create_action_section()
        self.create_footer()

    def create_header(self):
        """Top banner"""
        header_frame = tb.Frame(self)
        header_frame.pack(fill=X, pady=20)
        
        title = tb.Label(
            header_frame, 
            text="👁 PIXEL CIPHER", 
            font=("Helvetica", 22, "bold"), 
            bootstyle="info"
        )
        title.pack()
        
        subtitle = tb.Label(
            header_frame, 
            text="Advanced XOR Image Obfuscation Tool", 
            font=("Helvetica", 10), 
            bootstyle="secondary"
        )
        subtitle.pack()

    def create_source_section(self):
        """File selection and Preview area"""
        self.frame_source = tb.Labelframe(self, text=" 1. Source Image ", padding=15, bootstyle="primary")
        self.frame_source.pack(fill=X, padx=20, pady=10)

        # File Entry Row
        row_frame = tb.Frame(self.frame_source)
        row_frame.pack(fill=X)
        
        self.entry_file = tb.Entry(row_frame, bootstyle="secondary")
        self.entry_file.pack(side=LEFT, fill=X, expand=YES, padx=(0, 10))
        
        btn_browse = tb.Button(row_frame, text="📂 Browse", command=self.browse_file, bootstyle="outline-primary")
        btn_browse.pack(side=RIGHT)

        # Image Preview Area
        self.lbl_preview = tb.Label(
            self.frame_source, 
            text="[ No Image Selected ]", 
            font=("Consolas", 10), 
            bootstyle="secondary",
            anchor="center",
            relief="solid",
            borderwidth=1
        )
        self.lbl_preview.pack(fill=X, pady=(15, 0), ipady=40) # ipady gives it height

    def create_security_section(self):
        """Key Input"""
        frame_sec = tb.Labelframe(self, text=" 2. Security Key ", padding=15, bootstyle="warning")
        frame_sec.pack(fill=X, padx=20, pady=10)

        lbl_desc = tb.Label(frame_sec, text="Enter a secret phrase to lock the pixels:", bootstyle="secondary")
        lbl_desc.pack(anchor="w", pady=(0, 5))

        self.entry_key = tb.Entry(frame_sec, font=("Consolas", 12), bootstyle="warning")
        self.entry_key.insert(0, "v4kzy") # FIXED: Default key is v4kzy
        self.entry_key.pack(fill=X)

    def create_action_section(self):
        """Buttons"""
        frame_act = tb.Labelframe(self, text=" 3. Execute ", padding=15, bootstyle="success")
        frame_act.pack(fill=X, padx=20, pady=10)

        # Progress Bar (Hidden by default)
        self.progress = tb.Progressbar(frame_act, mode='indeterminate', bootstyle="info-striped")
        
        btn_frame = tb.Frame(frame_act)
        btn_frame.pack(fill=X)

        btn_enc = tb.Button(
            btn_frame, 
            text="🔒 ENCRYPT", 
            bootstyle="danger", 
            width=15,
            command=lambda: self.start_processing("encrypt")
        )
        btn_enc.pack(side=LEFT, padx=10, expand=YES)

        btn_dec = tb.Button(
            btn_frame, 
            text="🔓 DECRYPT", 
            bootstyle="success", 
            width=15,
            command=lambda: self.start_processing("decrypt")
        )
        btn_dec.pack(side=RIGHT, padx=10, expand=YES)

    def create_footer(self):
        """Status Bar"""
        self.lbl_status = tb.Label(self, text="Ready", bootstyle="secondary", font=("Helvetica", 10))
        self.lbl_status.pack(side=BOTTOM, pady=10)

    # --- LOGIC ---

    def browse_file(self):
        filename = filedialog.askopenfilename(filetypes=[("Images", "*.jpg;*.jpeg;*.png;*.bmp")])
        if filename:
            self.selected_file_path = filename
            self.entry_file.delete(0, END)
            self.entry_file.insert(0, filename)
            self.load_preview(filename)

    def load_preview(self, filepath):
        """Loads a small thumbnail of the image"""
        try:
            img = Image.open(filepath)
            img.thumbnail((400, 150)) # Resize to fit box
            self.preview_img = ImageTk.PhotoImage(img) # Keep reference!
            self.lbl_preview.config(image=self.preview_img, text="")
        except Exception:
            self.lbl_preview.config(text="[ Preview Unavailable ]", image="")

    def get_key_from_text(self, text_key):
        if not text_key: return 0
        total = sum(ord(char) for char in text_key)
        return total % 256

    def start_processing(self, action):
        """Starts the thread to prevent freezing"""
        if not self.selected_file_path:
            messagebox.showerror("Error", "Select an image first!")
            return
        
        # Show progress
        self.progress.pack(fill=X, pady=(0, 15))
        self.progress.start(10)
        self.lbl_status.config(text="Processing pixels... please wait.", bootstyle="info")
        
        # Run in background
        threading.Thread(target=self.process_image_thread, args=(action,), daemon=True).start()

    def process_image_thread(self, action):
        try:
            filepath = self.selected_file_path
            text_key = self.entry_key.get()
            numeric_key = self.get_key_from_text(text_key)

            img = Image.open(filepath)
            img = img.convert("RGB")
            pixels = img.load()
            width, height = img.size

            # Pixel Manipulation
            for x in range(width):
                for y in range(height):
                    r, g, b = pixels[x, y]
                    
                    # XOR
                    r_enc = r ^ numeric_key
                    g_enc = g ^ numeric_key
                    b_enc = b ^ numeric_key

                    # Channel Swap (B, G, R)
                    pixels[x, y] = (b_enc, g_enc, r_enc)

            # Save
            directory = os.path.dirname(filepath)
            filename = os.path.basename(filepath)
            
            if action == "encrypt":
                save_name = f"encrypted_{filename}"
            else:
                save_name = f"decrypted_{filename}"
                
            save_path = os.path.join(directory, save_name)
            img.save(save_path)

            # Update GUI safely
            self.after(0, lambda: self.finish_processing(save_path, True))

        except Exception as e:
             self.after(0, lambda: self.finish_processing(str(e), False))

    def finish_processing(self, result, success):
        """Runs on main thread after processing is done"""
        self.progress.stop()
        self.progress.pack_forget()
        
        if success:
            self.lbl_status.config(text=f"Saved: {os.path.basename(result)}", bootstyle="success")
            messagebox.showinfo("Success", f"Operation Complete!\nFile saved at:\n{result}")
            # Load the result into preview so user sees the change immediately
            self.load_preview(result)
        else:
            self.lbl_status.config(text="Error occurred", bootstyle="danger")
            messagebox.showerror("Error", f"Failed: {result}")

if __name__ == "__main__":
    app = ImageEncryptorApp()
    app.mainloop()
