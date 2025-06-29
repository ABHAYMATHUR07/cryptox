import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import Blowfish
import base64
import os
import subprocess
import platform


def pad(text, block_size):
    pad_len = block_size - len(text) % block_size
    return text + chr(pad_len) * pad_len

def unpad(text):
    pad_len = ord(text[-1])
    return text[:-pad_len]

# key generation
def generate_key_aes():
    return base64.b64encode(get_random_bytes(16)).decode()

def generate_key_des():
    return base64.b64encode(get_random_bytes(8)).decode()

def generate_key_blowfish():
    return base64.b64encode(get_random_bytes(16)).decode()

def generate_key_rsa():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key.decode(), public_key.decode()

def encrypt_aes(text, key):
    key = base64.b64decode(key)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text, AES.block_size).encode())
    iv = base64.b64encode(cipher.iv).decode()
    ct = base64.b64encode(ct_bytes).decode()
    return f"{iv}:{ct}"

def decrypt_aes(ciphertext, key):
    key = base64.b64decode(key)
    iv, ct = ciphertext.split(":")
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct).decode()
    return unpad(pt)

def encrypt_des(text, key):
    key = base64.b64decode(key)
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text, DES.block_size).encode())
    iv = base64.b64encode(cipher.iv).decode()
    ct = base64.b64encode(ct_bytes).decode()
    return f"{iv}:{ct}"

def decrypt_des(ciphertext, key):
    key = base64.b64decode(key)
    iv, ct = ciphertext.split(":")
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    pt = cipher.decrypt(ct).decode()
    return unpad(pt)

def encrypt_blowfish(text, key):
    key = base64.b64decode(key)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text, Blowfish.block_size).encode())
    iv = base64.b64encode(cipher.iv).decode()
    ct = base64.b64encode(ct_bytes).decode()
    return f"{iv}:{ct}"

def decrypt_blowfish(ciphertext, key):
    key = base64.b64decode(key)
    iv, ct = ciphertext.split(":")
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    pt = cipher.decrypt(ct).decode()
    return unpad(pt)

def encrypt_rsa(text, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ct = cipher.encrypt(text.encode())
    return base64.b64encode(ct).decode()

def decrypt_rsa(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    ct = base64.b64decode(ciphertext)
    pt = cipher.decrypt(ct)
    return pt.decode()

def open_file_location(file_path):
    folder = os.path.dirname(file_path)
    if platform.system() == "Windows":
        os.startfile(folder)
    elif platform.system() == "Darwin":
        subprocess.call(["open", folder])
    else:
        subprocess.call(["xdg-open", folder])

# --- GUI Application ---

class CryptoApp:
    def __init__(self, root):
        self.root = root
        root.title("Text Encryption & Decryption Tool")
        root.geometry("760x310")
        root.resizable(False, False)
        root.iconbitmap("key.ico")
        root.configure(bg="#6a8dad")
        self.algo_var = tk.StringVar(value="AES")
        self.key_text = tk.StringVar()
        self.public_key = ""
        self.private_key = ""

        tk.Label(root, text="Algorithm:",font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky="w",pady=5, padx=8)
        algo_menu = tk.OptionMenu(root, self.algo_var, "AES", "DES", "Blowfish", "RSA")
        algo_menu.config(bg="#bdddfc", fg="#000000", font=("Segoe UI", 11, "bold"), activebackground="#393e46", activeforeground="#eebbc3", bd=0)
        algo_menu["menu"].config(bg="#bdddfc", fg="#000000", font=("Segoe UI", 11))
        algo_menu.grid(row=0, column=1, sticky="w", pady=5, padx=5)

        tk.Label(root, text="Key:", font=("Segoe UI", 9, "bold")).grid(row=1, column=0, sticky="w",pady=5, padx=8)
        self.key_entry = tk.Entry(root, textvariable=self.key_text, width=60)
        self.key_entry.grid(row=1, column=1, sticky="w")
        tk.Button(root, text="Generate Key",height=1, width=12, bg="#bdddfc", fg="black", font=("Segoe UI", 9, "bold"),command=self.generate_key).grid(row=1, column=2, sticky="w",pady=5, padx=8)
        tk.Button(root, text="Copy Key",height=1, width=12, bg="#bdddfc", fg="black",font=("Segoe UI", 9, "bold"), command=self.copy_key).grid(row=1, column=3, sticky="w")
        tk.Button(root, text="Save Key to File", height=1, width=12, bg="#bdddfc", fg="black", font=("Segoe UI", 9, "bold"), command=self.save_key_to_file).grid(row=1, column=4, sticky="w")

        tk.Label(root, text="Input Text:",font=("Segoe UI", 9, "bold")).grid(row=2, column=0, sticky="nw",pady=5, padx=8)
        self.input_text = scrolledtext.ScrolledText(root, width=60, height=5)
        self.input_text.grid(row=2, column=1, columnspan=3, sticky="w")

        tk.Label(root, text="Output:",font=("Segoe UI", 9, "bold")).grid(row=3, column=0, sticky="nw",pady=5, padx=8)
        self.output_text = scrolledtext.ScrolledText(root, width=60, height=5)
        self.output_text.grid(row=3, column=1, columnspan=3, sticky="w")

        tk.Button(root, text="Encrypt",height=1, width=12, bg="#bdddfc", fg="black",font=("Segoe UI", 10, "bold"), command=self.encrypt_text).grid(row=4, column=1, sticky="w")
        tk.Button(root, text="Decrypt",height=1, width=12, bg="#bdddfc", fg="black",font=("Segoe UI", 10, "bold"), command=self.decrypt_text).grid(row=4, column=2, sticky="w")
        tk.Button(root, text="Copy Output",height=1, width=12, bg="#bdddfc", fg="black",font=("Segoe UI", 10, "bold"), command=self.copy_output).grid(row=4, column=3, sticky="w")

        tk.Button(root, text="Encrypt File", height=1, width=12, bg="#bdddfc", fg="black",font=("Segoe UI", 10, "bold"),command=self.encrypt_file).grid(row=5, column=1, sticky="w")
        tk.Button(root, text="Decrypt File",height=1, width=12, bg="#bdddfc", fg="black",font=("Segoe UI", 10, "bold"), command=self.decrypt_file).grid(row=5, column=2, sticky="w")

    def generate_key(self):
        algo = self.algo_var.get()
        if algo == "AES":
            self.key_text.set(generate_key_aes())
        elif algo == "DES":
            self.key_text.set(generate_key_des())
        elif algo == "Blowfish":
            self.key_text.set(generate_key_blowfish())
        elif algo == "RSA":
            priv, pub = generate_key_rsa()
            self.private_key = priv
            self.public_key = pub
            self.key_text.set(pub)
            with open("private_key.pem", "w") as f:
                f.write(priv)
            messagebox.showinfo("RSA Keys", "Public key set. Private key saved as private_key.pem")

    def save_key_to_file(self):
        key = self.key_text.get()
        if not key:
            messagebox.showerror("Error", "No key to save.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key Files", "*.key")])
        if file_path:
            with open(file_path, "w") as f:
                f.write(key)
            messagebox.showinfo("Saved", f"Key saved to {file_path}")

    def copy_key(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.key_text.get())
        messagebox.showinfo("Copied", "Key copied to clipboard.")

    def copy_output(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.output_text.get("1.0", tk.END).strip())
        messagebox.showinfo("Copied", "Output copied to clipboard.")

    def encrypt_text(self):
        algo = self.algo_var.get()
        text = self.input_text.get("1.0", tk.END).strip()
        key = self.key_text.get()
        try:
            if algo == "AES":
                result = encrypt_aes(text, key)
            elif algo == "DES":
                result = encrypt_des(text, key)
            elif algo == "Blowfish":
                result = encrypt_blowfish(text, key)
            elif algo == "RSA":
                result = encrypt_rsa(text, key)
            else:
                result = "Unsupported algorithm."
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, result)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_text(self):
        algo = self.algo_var.get()
        text = self.input_text.get("1.0", tk.END).strip()
        key = self.key_text.get()
        try:
            if algo == "AES":
                result = decrypt_aes(text, key)
            elif algo == "DES":
                result = decrypt_des(text, key)
            elif algo == "Blowfish":
                result = decrypt_blowfish(text, key)
            elif algo == "RSA":
                result = decrypt_rsa(text, self.private_key or key)
            else:
                result = "Unsupported algorithm."
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, result)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def encrypt_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        algo = self.algo_var.get()
        key = self.key_text.get()
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = f.read()
            if algo == "AES":
                enc = encrypt_aes(data, key)
            elif algo == "DES":
                enc = encrypt_des(data, key)
            elif algo == "Blowfish":
                enc = encrypt_blowfish(data, key)
            elif algo == "RSA":
                enc = encrypt_rsa(data, key)
            else:
                messagebox.showerror("Error", "Unsupported algorithm.")
                return
            out_path = file_path + ".enc"
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(enc)
            messagebox.showinfo("Success", f"Encrypted file saved as {out_path}")
            open_file_location(out_path)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        algo = self.algo_var.get()
        key = self.key_text.get()
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = f.read()
            if algo == "AES":
                dec = decrypt_aes(data, key)
            elif algo == "DES":
                dec = decrypt_des(data, key)
            elif algo == "Blowfish":
                dec = decrypt_blowfish(data, key)
            elif algo == "RSA":
                dec = decrypt_rsa(data, self.private_key or key)
            else:
                messagebox.showerror("Error", "Unsupported algorithm.")
                return
            out_path = file_path + ".dec"
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(dec)
            messagebox.showinfo("Success", f"Decrypted file saved as {out_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
