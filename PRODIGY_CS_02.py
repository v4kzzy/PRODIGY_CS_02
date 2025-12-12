import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import json
import threading
import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- CONFIGURATION & THEME ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# =================================================
# BACKEND: THE CRYPTO ENGINE
# =================================================
class ImageEncryptor:
    def __init__(self, key_hex: str):
        try:
            self.key = bytes.fromhex(key_hex)
            if len(self.key) != 32:
                raise ValueError
        except:
            raise ValueError("Key must be a valid 64-character hex string (32 bytes).")
        self.backend = default_backend()

    @staticmethod
    def generate_key_hex() -> str:
        return os.urandom(32).hex()

    def _get_image_bytes(self, image_path):
        with Image.open(image_path) as img:
            img = img.convert("RGB")
            img_array = np.array(img)
            shape = img_array.shape
            mode = img.mode
            flat_bytes = img_array.tobytes()
            return flat_bytes, shape, mode

    def _bytes_to_image(self, flat_bytes, shape, mode, output_path):
        img_array = np.frombuffer(flat_bytes, dtype=np.uint8).reshape(shape)
        img = Image.fromarray(img_array, mode)
        img.save(output_path, format='PNG')

    def _crypt_data(self, data, nonce):
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def calculate_entropy(self, image_path):
        """Calculates Shannon Entropy to verify randomness."""
        with Image.open(image_path) as img:
            arr = np.array(img).flatten()
            counts = np.bincount(arr, minlength=256)
            p = counts / arr.size
            p = p[p > 0]
            return -np.sum(p * np.log2(p))

    def encrypt(self, input_path, output_path, meta_path):
        raw_bytes, shape, mode = self._get_image_bytes(input_path)
        nonce = os.urandom(16)
        encrypted_bytes = self._crypt_data(raw_bytes, nonce)
        
        self._bytes_to_image(encrypted_bytes, shape, mode, output_path)
        
        metadata = {'shape': shape, 'mode': mode, 'nonce_hex': nonce.hex()}
        with open(meta_path, 'w') as f:
            json.dump(metadata, f)
        
        return self.calculate_entropy(output_path)

    def decrypt(self, input_path, meta_path, output_path):
        with open(meta_path, 'r') as f:
            metadata = json.load(f)
        
        nonce = bytes.fromhex(metadata['nonce_hex'])
        shape = tuple(metadata['shape'])
        mode = metadata['mode']
        
        encrypted_bytes, current_shape, _ = self._get_image_bytes(input_path)
        
        if current_shape != shape:
            raise ValueError("Size mismatch! Image dimensions do not match metadata.")
            
        decrypted_bytes = self._crypt_data(encrypted_bytes, nonce)
        self._bytes_to_image(decrypted_bytes, shape, mode, output_path)

# =================================================
# FRONTEND: THE GUI
# =================================================
class AegisApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Aegis // AES-256 Image Encryption")
        self.geometry("900x650")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- SIDEBAR ---
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo = ctk.CTkLabel(self.sidebar, text="AEGIS\nCRYPTO", font=ctk.CTkFont(size=24, weight="bold"))
        self.logo.grid(row=0, column=0, padx=20, pady=(30, 20))
        
        self.desc = ctk.CTkLabel(self.sidebar, text="Secure AES-256 CTR\nPixel Encryption", text_color="gray")
        self.desc.grid(row=1, column=0, padx=20)

        # --- MAIN AREA ---
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        
        self.tab_enc = self.tabview.add("ENCRYPT IMAGE")
        self.tab_dec = self.tabview.add("DECRYPT IMAGE")

        self.setup_encryption_tab()
        self.setup_decryption_tab()

    def log(self, message):
        """Helper to write to the text box on the active tab."""
        # Find which tab is active and write to its textbox
        if self.tabview.get() == "ENCRYPT IMAGE":
            box = self.log_box_enc
        else:
            box = self.log_box_dec
        
        box.configure(state="normal")
        box.insert("end", f"> {message}\n")
        box.see("end")
        box.configure(state="disabled")

    # ---------------- UI SETUP: ENCRYPTION ----------------
    def setup_encryption_tab(self):
        # File Selection
        self.btn_load_enc = ctk.CTkButton(self.tab_enc, text="1. Select Image", command=self.select_file_enc)
        self.btn_load_enc.pack(pady=10, fill="x", padx=50)
        
        self.lbl_file_enc = ctk.CTkLabel(self.tab_enc, text="No file selected", text_color="gray")
        self.lbl_file_enc.pack()

        # Key Management
        self.key_frame = ctk.CTkFrame(self.tab_enc, fg_color="transparent")
        self.key_frame.pack(pady=20, fill="x", padx=50)
        
        self.entry_key_enc = ctk.CTkEntry(self.key_frame, placeholder_text="Enter 64-char Hex Key or Generate")
        self.entry_key_enc.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.btn_gen_key = ctk.CTkButton(self.key_frame, text="Generate Key", width=100, command=self.generate_key_ui, fg_color="#F1C40F", text_color="black")
        self.btn_gen_key.pack(side="right")

        # Action
        self.btn_run_enc = ctk.CTkButton(self.tab_enc, text="ENCRYPT NOW", command=self.run_encryption_thread, fg_color="#E74C3C", height=40, font=ctk.CTkFont(weight="bold"))
        self.btn_run_enc.pack(pady=20, fill="x", padx=50)

        # Log
        self.log_box_enc = ctk.CTkTextbox(self.tab_enc, height=200, font=ctk.CTkFont(family="Consolas", size=12))
        self.log_box_enc.pack(fill="both", expand=True, padx=20, pady=10)
        self.log_box_enc.configure(state="disabled")

    # ---------------- UI SETUP: DECRYPTION ----------------
    def setup_decryption_tab(self):
        # File Selection (Encrypted Image)
        self.btn_load_dec = ctk.CTkButton(self.tab_dec, text="1. Select Encrypted PNG", command=self.select_file_dec)
        self.btn_load_dec.pack(pady=10, fill="x", padx=50)
        self.lbl_file_dec = ctk.CTkLabel(self.tab_dec, text="No file selected", text_color="gray")
        self.lbl_file_dec.pack()

        # Metadata Selection
        self.btn_load_meta = ctk.CTkButton(self.tab_dec, text="2. Select Metadata JSON", command=self.select_meta_dec)
        self.btn_load_meta.pack(pady=10, fill="x", padx=50)
        self.lbl_meta_dec = ctk.CTkLabel(self.tab_dec, text="No metadata selected", text_color="gray")
        self.lbl_meta_dec.pack()

        # Key Entry
        self.entry_key_dec = ctk.CTkEntry(self.tab_dec, placeholder_text="Enter the Master Key used for encryption")
        self.entry_key_dec.pack(pady=10, fill="x", padx=50)

        # Action
        self.btn_run_dec = ctk.CTkButton(self.tab_dec, text="DECRYPT RESTORE", command=self.run_decryption_thread, fg_color="#2ECC71", height=40, font=ctk.CTkFont(weight="bold"))
        self.btn_run_dec.pack(pady=20, fill="x", padx=50)

        # Log
        self.log_box_dec = ctk.CTkTextbox(self.tab_dec, height=150, font=ctk.CTkFont(family="Consolas", size=12))
        self.log_box_dec.pack(fill="both", expand=True, padx=20, pady=10)
        self.log_box_dec.configure(state="disabled")

    # ---------------- LOGIC HANDLERS ----------------
    def select_file_enc(self):
        f = filedialog.askopenfilename(filetypes=[("Images", "*.jpg *.png *.jpeg *.bmp")])
        if f:
            self.lbl_file_enc.configure(text=os.path.basename(f))
            self.target_enc = f

    def select_file_dec(self):
        f = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png")])
        if f:
            self.lbl_file_dec.configure(text=os.path.basename(f))
            self.target_dec = f

    def select_meta_dec(self):
        f = filedialog.askopenfilename(filetypes=[("JSON Data", "*.json")])
        if f:
            self.lbl_meta_dec.configure(text=os.path.basename(f))
            self.target_meta = f

    def generate_key_ui(self):
        k = ImageEncryptor.generate_key_hex()
        self.entry_key_enc.delete(0, "end")
        self.entry_key_enc.insert(0, k)
        self.log(f"Generated new secure key: {k[:10]}...")

    def run_encryption_thread(self):
        threading.Thread(target=self.process_encryption).start()

    def run_decryption_thread(self):
        threading.Thread(target=self.process_decryption).start()

    def process_encryption(self):
        try:
            if not hasattr(self, 'target_enc'):
                messagebox.showerror("Error", "Please select an image first.")
                return
            
            key = self.entry_key_enc.get().strip()
            if not key:
                messagebox.showerror("Error", "Please enter or generate a key.")
                return

            self.btn_run_enc.configure(state="disabled", text="Encrypting...")
            
            # Paths
            folder = os.path.dirname(self.target_enc)
            base = os.path.splitext(os.path.basename(self.target_enc))[0]
            out_img = os.path.join(folder, f"ENC_{base}.png")
            out_meta = os.path.join(folder, f"META_{base}.json")

            # Execute
            engine = ImageEncryptor(key)
            self.log("Starting AES-256 CTR Encryption...")
            entropy = engine.encrypt(self.target_enc, out_img, out_meta)
            
            self.log(f"Encryption Complete!")
            self.log(f"Saved: {os.path.basename(out_img)}")
            self.log(f"Meta:  {os.path.basename(out_meta)}")
            self.log("-" * 30)
            self.log(f"ENTROPY SCORE: {entropy:.4f}")
            self.log("Note: > 7.99 indicates perfect encryption.")
            
            messagebox.showinfo("Success", f"Encryption Done!\n\nIMPORTANT: Save your KEY safely.\nIf you lose the key, the image is gone forever.\n\nKey: {key}")

        except Exception as e:
            self.log(f"Error: {e}")
            messagebox.showerror("Error", str(e))
        finally:
            self.btn_run_enc.configure(state="normal", text="ENCRYPT NOW")

    def process_decryption(self):
        try:
            if not hasattr(self, 'target_dec') or not hasattr(self, 'target_meta'):
                messagebox.showerror("Error", "Please select both the Encrypted Image and the Metadata JSON.")
                return
            
            key = self.entry_key_dec.get().strip()
            if not key:
                messagebox.showerror("Error", "Please enter the decryption key.")
                return

            self.btn_run_dec.configure(state="disabled", text="Decrypting...")
            
            # Paths
            folder = os.path.dirname(self.target_dec)
            out_img = os.path.join(folder, "RESTORED_Image.png")

            # Execute
            engine = ImageEncryptor(key)
            self.log("Starting AES-256 Decryption...")
            engine.decrypt(self.target_dec, self.target_meta, out_img)
            
            self.log(f"Decryption Complete!")
            self.log(f"Restored to: {os.path.basename(out_img)}")
            
            messagebox.showinfo("Success", "Image restored successfully!")

        except Exception as e:
            self.log(f"Error: {e}")
            messagebox.showerror("Decryption Failed", f"Failed to decrypt.\nCheck your Key and Files.\n\nError: {e}")
        finally:
            self.btn_run_dec.configure(state="normal", text="DECRYPT RESTORE")

if __name__ == "__main__":
    app = AegisApp()
    app.mainloop()
