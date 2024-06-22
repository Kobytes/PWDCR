import tkinter as tk
from tkinter import messagebox, filedialog
import json
import string
import os
import logging
from secrets import choice, SystemRandom
from cryptography.fernet import Fernet
from zxcvbn import zxcvbn

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Secure random number generator
secure_rng = SystemRandom()

# Encryption key generation
def generate_key():
    return Fernet.generate_key()

# Password generation using secrets module for cryptographic security
def generate_password(length=12, include_upper=True, include_digits=True, include_special=True, exclude_chars=''):
    characters = string.ascii_lowercase
    if include_upper:
        characters += string.ascii_uppercase
    if include_digits:
        characters += string.digits
    if include_special:
        characters += string.punctuation

    if exclude_chars:
        characters = ''.join(c for c in characters if c not in exclude_chars)

    if not characters:
        logging.error("Aucun caractère à utiliser pour générer le mot de passe.")
        return ""

    password = ''.join(secure_rng.choice(characters) for _ in range(length))
    return password

# Password encryption
def encrypt_password(password, key):
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    return encrypted_password

# Password decryption
def decrypt_password(encrypted_password, key):
    fernet = Fernet(key)
    decrypted_password = fernet.decrypt(encrypted_password).decode()
    return decrypted_password

# Initialize JSON file to store passwords
def init_password_storage(file_path='passwords.json'):
    try:
        with open(file_path, 'r') as file:
            passwords = json.load(file)
    except FileNotFoundError:
        passwords = {}
        with open(file_path, 'w') as file:
            json.dump(passwords, file)
        os.chmod(file_path, 0o600) # Restrict file permissions to owner only
    return passwords

# Save encrypted passwords in JSON file
def save_password_to_json(encrypted_password, file_path='passwords.json'):
    passwords = init_password_storage(file_path)
    passwords[len(passwords) + 1] = encrypted_password.decode()
    with open(file_path, 'w') as file:
        json.dump(passwords, file)

# Reading the encryption key
def load_key(key_path='secret.key'):
    try:
        with open(key_path, 'rb') as key_file:
            key = key_file.read()
    except FileNotFoundError:
        key = generate_key()
        with open(key_path, 'wb') as key_file:
            key_file.write(key)
        os.chmod(key_path, 0o600) # Restrict file permissions to owner only
    return key

# Password strength check
def check_password_strength(password):
    if not password:
        return 0, "Mot de passe vide ou trop court"

    result = zxcvbn(password)
    score = result['score']
    feedback = result['feedback']

    if score >= 3:
        feedback_message = 'Votre mot de passe semble assez fort !'
    else:
        feedback_message = ''
        if feedback['warning']:
            feedback_message += f"Attention : {feedback['warning']}\n"
        if feedback['suggestions']:
            feedback_message += "Suggestions :\n" + "\n".join([f"  - {suggestion}" for suggestion in feedback['suggestions']])

    return score, feedback_message

# Update password strength indicator
def update_password_strength(event=None):
    try:
        length = int(entry_length.get() or 0)
    except ValueError:
        length = 0

    include_upper = var_upper.get()
    include_digits = var_digits.get()
    include_special = var_special.get()
    exclude_chars = entry_exclude.get()

    if length > 0:
        password = generate_password(length, include_upper, include_digits, include_special, exclude_chars)
        score, feedback = check_password_strength(password)
    else:
        score = 0
        feedback = "Longueur de mot de passe invalide"

    # Visual indicator update
    strength_label.config(text=f"Force estimée : {score}/4\n{feedback}")

# Function to display decrypted passwords
def show_decrypted_passwords():
    key_path = filedialog.askopenfilename(title="Sélectionner le fichier de clé", filetypes=[("Key Files", "*.key")])
    if not key_path:
        return

    try:
        with open(key_path, 'rb') as key_file:
            key = key_file.read()
    except Exception as e:
        messagebox.showerror("Erreur", f"Erreur lors du chargement de la clé : {e}")
        return

    try:
        with open('passwords.json', 'r') as file:
            encrypted_passwords = json.load(file)
    except Exception as e:
        messagebox.showerror("Erreur", f"Erreur lors du chargement des mots de passe : {e}")
        return

    decrypted_passwords = []
    fernet = Fernet(key)

    for enc_password in encrypted_passwords.values():
        try:
            decrypted_password = fernet.decrypt(enc_password.encode()).decode()
            decrypted_passwords.append(decrypted_password)
        except Exception as e:
            decrypted_passwords.append(f"Erreur de déchiffrement : {e}")

    if decrypted_passwords:
        messagebox.showinfo("Mots de passe déchiffrés", "\n".join(decrypted_passwords))
    else:
        messagebox.showinfo("Mots de passe déchiffrés", "Aucun mot de passe trouvé ou déchiffré.")

# Function to generate and save password
def generate_and_save_password():
    try:
        length = int(entry_length.get())
    except ValueError:
        messagebox.showerror("Erreur", "Veuillez entrer une longueur valide.")
        return

    include_upper = var_upper.get()
    include_digits = var_digits.get()
    include_special = var_special.get()
    exclude_chars = entry_exclude.get()
    try:
        num_passwords = int(entry_num_passwords.get())
    except ValueError:
        messagebox.showerror("Erreur", "Veuillez entrer un nombre valide de mots de passe.")
        return

    passwords = []
    key = load_key()

    for _ in range(num_passwords):
        password = generate_password(length, include_upper, include_digits, include_special, exclude_chars)
        passwords.append(password)

        encrypted_password = encrypt_password(password, key)
        save_password_to_json(encrypted_password)

    messagebox.showinfo("Mots de passe générés", f"Mots de passe générés :\n" +
                        "\n".join(passwords))

# Configuring the tkinter window
root = tk.Tk()
root.title("PWDCR - Générateur de mots de passe")

tk.Label(root, text="Longueur du mot de passe:").pack(pady=5)
entry_length = tk.Entry(root)
entry_length.pack(pady=5)
entry_length.insert(0, "12")
entry_length.bind("<KeyRelease>", update_password_strength)

tk.Label(root, text="Caractères à exclure:").pack(pady=5)
entry_exclude = tk.Entry(root)
entry_exclude.pack(pady=5)
entry_exclude.insert(0, "")
entry_exclude.bind("<KeyRelease>", update_password_strength)

tk.Label(root, text="Nombre de mots de passe:").pack(pady=5)
entry_num_passwords = tk.Entry(root)
entry_num_passwords.pack(pady=5)
entry_num_passwords.insert(0, "1")

var_upper = tk.BooleanVar()
var_digits = tk.BooleanVar()
var_special = tk.BooleanVar()

check_frame = tk.Frame(root)
check_frame.pack(pady=10)
tk.Checkbutton(check_frame, text="Inclure des majuscules", variable=var_upper, command=update_password_strength).pack(side='left', padx=10)
tk.Checkbutton(check_frame, text="Inclure des chiffres", variable=var_digits, command=update_password_strength).pack(side='left', padx=10)
tk.Checkbutton(check_frame, text="Inclure des caractères spéciaux", variable=var_special, command=update_password_strength).pack(side='left', padx=10)

strength_label = tk.Label(root, text="Force estimée :")
strength_label.pack(pady=5)

# Button to generate and save password
tk.Button(root, text="Générer et sauvegarder le mot de passe", command=generate_and_save_password).pack(pady=20)

# Button to display decrypted passwords
tk.Button(root, text="Afficher les mots de passe déchiffrés", command=show_decrypted_passwords).pack(pady=10)

update_password_strength()

root.mainloop()
