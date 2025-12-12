# 🛡️ Professional Image Encryption Tool

> **A secure, lossless image encryption application using AES-256 (CTR Mode) with real-time entropy analysis.**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Cryptography](https://img.shields.io/badge/Security-AES--256-green)
![GUI](https://img.shields.io/badge/UI-CustomTkinter-orange)

## 📖 Overview

**Aegis** is a cybersecurity tool designed to encrypt image data at the pixel level. Unlike simple "steganography" or weak XOR tools, Aegis uses industry-standard **AES-256 encryption in Counter (CTR) mode**. This turns your images into cryptographic noise, mathematically indistinguishable from random data.

It features a modern Dark Mode GUI and includes a built-in **Shannon Entropy Calculator** to mathematically prove the randomness (and security) of the encrypted output.

 
*(Add a screenshot of your tool here)*

---

## ✨ Key Features

* **🔒 AES-256 Encryption:** Uses the `cryptography` library for military-grade security.
* **🖼️ Lossless Reconstruction:** Decrypted images are pixel-perfect matches to the original.
* **📊 Entropy Analysis:** Automatically calculates and displays the Shannon Entropy score (0-8.0) to verify encryption quality.
* **⚡ Threaded Performance:** Keeps the UI responsive even when processing large 4K images.
* **🎨 Modern Dashboard:** Built with `customtkinter` for a professional dark-themed experience.

---

## 🛠️ Installation

1.  **Clone the repository** (or download the files):
    ```bash
    git clone [https://github.com/yourusername/aegis-encryptor.git](https://github.com/yourusername/aegis-encryptor.git)
    cd aegis-encryptor
    ```

2.  **Install the required dependencies:**
    ```bash
    pip install customtkinter pillow numpy cryptography
    ```

---

## 🚀 Usage

### 1. Launch the App
Run the main script:
```bash
python main_gui.py
