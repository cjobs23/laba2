import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives import serialization
import os
import base64

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryption/Decryption Tool")
        self.root.geometry("800x600")
        
        # Create main container
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # File selection
        ttk.Label(self.main_frame, text="Select File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.file_path = tk.StringVar()
        ttk.Entry(self.main_frame, textvariable=self.file_path, width=50).grid(row=0, column=1, pady=5)
        ttk.Button(self.main_frame, text="Browse", command=self.browse_file).grid(row=0, column=2, pady=5)
        
        # Password entry
        ttk.Label(self.main_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.password = tk.StringVar()
        ttk.Entry(self.main_frame, textvariable=self.password, show="*", width=50).grid(row=1, column=1, pady=5)
        
        # Operation buttons
        ttk.Button(self.main_frame, text="Encrypt (AES-CBC)", command=self.encrypt_file).grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Button(self.main_frame, text="Decrypt (AES-CBC)", command=self.decrypt_file).grid(row=2, column=1, columnspan=2, pady=10)
        
        # RSA buttons
        ttk.Button(self.main_frame, text="Generate RSA Keys", command=self.generate_rsa_keys).grid(row=5, column=0, pady=10)
        ttk.Button(self.main_frame, text="Encrypt (RSA)", command=self.rsa_encrypt_file).grid(row=5, column=1, pady=10)
        ttk.Button(self.main_frame, text="Decrypt (RSA)", command=self.rsa_decrypt_file).grid(row=5, column=2, pady=10)
        ttk.Button(self.main_frame, text="Sign File", command=self.sign_file).grid(row=6, column=1, pady=10)
        ttk.Button(self.main_frame, text="Verify Signature", command=self.verify_signature).grid(row=6, column=2, pady=10)
        
        # Progress bar
        self.progress = ttk.Progressbar(self.main_frame, length=300, mode='determinate')
        self.progress.grid(row=3, column=0, columnspan=3, pady=10)
        
        # Status label
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        ttk.Label(self.main_frame, textvariable=self.status_var).grid(row=4, column=0, columnspan=3)

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)

    def update_status(self, message):
        self.status_var.set(message)
        self.root.update()

    def generate_key(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key, salt

    def encrypt_file(self):
        if not self.file_path.get() or not self.password.get():
            messagebox.showerror("Error", "Please select a file and enter a password")
            return

        try:
            # Generate key and IV
            iv = os.urandom(16)
            key, salt = self.generate_key(self.password.get())

            # Read input file
            with open(self.file_path.get(), 'rb') as file:
                data = file.read()

            # Pad the data
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()

            # Encrypt the data
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            # Generate MAC
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(encrypted_data)
            mac = h.finalize()

            # Combine all data
            output_data = salt + iv + mac + encrypted_data

            # Save encrypted file
            output_path = self.file_path.get() + '.encrypted'
            with open(output_path, 'wb') as file:
                file.write(output_data)

            self.update_status(f"File encrypted successfully: {output_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            self.update_status("Encryption failed")

    def decrypt_file(self):
        if not self.file_path.get() or not self.password.get():
            messagebox.showerror("Error", "Please select a file and enter a password")
            return

        try:
            # Read encrypted file
            with open(self.file_path.get(), 'rb') as file:
                encrypted_data = file.read()

            # Extract components
            salt = encrypted_data[:16]
            iv = encrypted_data[16:32]
            mac = encrypted_data[32:64]
            ciphertext = encrypted_data[64:]

            # Regenerate key
            key, _ = self.generate_key(self.password.get(), salt)

            # Verify MAC
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(ciphertext)
            h.verify(mac)

            # Decrypt data
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()

            # Remove padding
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()

            # Save decrypted file
            output_path = self.file_path.get() + '.decrypted'
            with open(output_path, 'wb') as file:
                file.write(data)

            self.update_status(f"File decrypted successfully: {output_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            self.update_status("Decryption failed")

    def generate_rsa_keys(self):
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            # Serialize private key
            pem_private = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Serialize public key
            pem_public = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Save keys to files
            with open('private_key.pem', 'wb') as f:
                f.write(pem_private)
            with open('public_key.pem', 'wb') as f:
                f.write(pem_public)
                
            self.update_status("RSA keys generated successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {str(e)}")

    def load_public_key(self):
        try:
            with open('public_key.pem', 'rb') as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            return public_key
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load public key: {str(e)}")
            return None

    def load_private_key(self):
        try:
            with open('private_key.pem', 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            return private_key
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load private key: {str(e)}")
            return None

    def rsa_encrypt_file(self):
        if not self.file_path.get():
            messagebox.showerror("Error", "Please select a file")
            return

        try:
            public_key = self.load_public_key()
            if not public_key:
                return

            with open(self.file_path.get(), 'rb') as file:
                data = file.read()

            # RSA can only encrypt data up to a certain size, so we'll use hybrid encryption
            # Generate a random AES key and encrypt the file with it
            aes_key = os.urandom(32)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Encrypt the AES key with RSA
            encrypted_key = public_key.encrypt(
                aes_key,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Pad and encrypt the data
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            # Save encrypted file
            output_path = self.file_path.get() + '.rsa_encrypted'
            with open(output_path, 'wb') as file:
                file.write(len(encrypted_key).to_bytes(4, byteorder='big'))
                file.write(encrypted_key)
                file.write(iv)
                file.write(encrypted_data)

            self.update_status(f"File encrypted with RSA: {output_path}")

        except Exception as e:
            messagebox.showerror("Error", f"RSA encryption failed: {str(e)}")

    def rsa_decrypt_file(self):
        if not self.file_path.get():
            messagebox.showerror("Error", "Please select a file")
            return

        try:
            private_key = self.load_private_key()
            if not private_key:
                return

            with open(self.file_path.get(), 'rb') as file:
                # Read the encrypted key length
                key_length = int.from_bytes(file.read(4), byteorder='big')
                # Read the encrypted key
                encrypted_key = file.read(key_length)
                # Read the IV
                iv = file.read(16)
                # Read the encrypted data
                encrypted_data = file.read()

            # Decrypt the AES key
            aes_key = private_key.decrypt(
                encrypted_key,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Decrypt the data
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # Remove padding
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()

            # Save decrypted file
            output_path = self.file_path.get() + '.rsa_decrypted'
            with open(output_path, 'wb') as file:
                file.write(data)

            self.update_status(f"File decrypted with RSA: {output_path}")

        except Exception as e:
            messagebox.showerror("Error", f"RSA decryption failed: {str(e)}")

    def sign_file(self):
        if not self.file_path.get():
            messagebox.showerror("Error", "Please select a file")
            return

        try:
            private_key = self.load_private_key()
            if not private_key:
                return

            with open(self.file_path.get(), 'rb') as file:
                data = file.read()

            signature = private_key.sign(
                data,
                asymmetric_padding.PSS(
                    mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                    salt_length=asymmetric_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Save signature
            with open(self.file_path.get() + '.sig', 'wb') as file:
                file.write(signature)

            self.update_status("File signed successfully")

        except Exception as e:
            messagebox.showerror("Error", f"Signing failed: {str(e)}")

    def verify_signature(self):
        if not self.file_path.get():
            messagebox.showerror("Error", "Please select a file")
            return

        try:
            public_key = self.load_public_key()
            if not public_key:
                return

            # Read the original file
            with open(self.file_path.get(), 'rb') as file:
                data = file.read()

            # Read the signature
            with open(self.file_path.get() + '.sig', 'rb') as file:
                signature = file.read()

            # Verify the signature
            public_key.verify(
                signature,
                data,
                asymmetric_padding.PSS(
                    mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                    salt_length=asymmetric_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            self.update_status("Signature verified successfully")
            messagebox.showinfo("Success", "Signature is valid")

        except Exception as e:
            messagebox.showerror("Error", f"Signature verification failed: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
