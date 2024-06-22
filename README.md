# PWDCR

A secure password generator with encryption and real-time strength evaluation using Tkinter and Python.

## Description

This project provides a graphical user interface (GUI) for generating secure passwords. It includes features such as:

- Password generation with customizable criteria (length, character sets).
- Real-time evaluation of password strength.
- Encryption of generated passwords using Fernet (symmetric encryption).
- Storage of encrypted passwords in a JSON file.
- Decryption and display of stored passwords using a provided key.

## Features

- **Password Generation**: Create passwords with options for length, inclusion of uppercase letters, digits, and special characters.
- **Password Strength Evaluation**: Instant feedback on password strength using the zxcvbn library.
- **Encryption**: Securely encrypt passwords using Fernet encryption.
- **Storage**: Save encrypted passwords in a JSON file.
- **Decryption**: Decrypt and display stored passwords using a secret key.

## Installation

1. **Clone the repository**:

```bash
git clone https://github.com/Kobytes/PWDCR.git
cd PWDCR
```
2. **Install dependencies**:

```bash
pip install -r requirements.txt
```

3. **Run the application**:

```bash
python3 pwdcr.py
```
