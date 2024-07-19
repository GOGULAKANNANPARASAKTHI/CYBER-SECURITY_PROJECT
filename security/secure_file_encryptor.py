import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def pad_data(data):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    return padder.update(data) + padder.finalize()

def encrypt_file(key, filename, iv):
    # Configure AES cipher with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt file content
    with open(filename, 'rb') as file:
        plaintext = file.read()
        padded_plaintext = pad_data(plaintext)
        ciphered = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Write encrypted data to a new file
    with open(f'{filename}.enc', 'wb') as file:
        file.write(iv + ciphered)

def decrypt_file(key, filename, iv):
    # Read encrypted file
    with open(f'{filename}.enc', 'rb') as f:
        encrypted_data = f.read()

    # Extract IV from the encrypted data
    extracted_iv = encrypted_data[:16]
    encrypted_content = encrypted_data[16:]

    # Configure AES cipher with CBC mode and the extracted IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(extracted_iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt and unpad data
    decrypted_data = decryptor.update(encrypted_content) + decryptor.finalize()
    unpadded_data = unpad_data(decrypted_data)
    return unpadded_data

def unpad_data(data):
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def main():
    password = input("Enter password: ")
    key = generate_key(password)
    iv = os.urandom(16)  # Generate IV

    choice = input("Encrypt (e) or Decrypt (d)? ").strip().lower()
    filename = input("Enter filename: ")

    if choice == 'e':
        encrypt_file(key, filename, iv)
        print(f'{filename} encrypted successfully.')
    elif choice == 'd':
        decrypted_data = decrypt_file(key, filename, iv)
        with open(f'{filename}.decrypted', 'wb') as file:
            file.write(decrypted_data)
        print(f'{filename}.enc decrypted successfully.')
    else:
        print("Invalid choice. Please choose 'e' for encrypt or 'd' for decrypt.")

if __name__ == "__main__":
    main()
