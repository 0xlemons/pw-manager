import threading
import webbrowser
from flask import Flask, render_template, request, redirect, session
import webview
import os
import sys
from getpass import getpass
from colorama import Fore
import appdirs
import pickle
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pyperclip


# hides consol messages
sys.stdout = open(os.devnull, 'w')
sys.stderr = open(os.devnull, 'w')


master = 'add master fernet key here'
private = b' add master hazmet key'
app = Flask(__name__)

app.secret_key = b'choose a random key'

def generate_key():
    return Fernet.generate_key()


def encrypt_password(password, key):
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password

def decrypt_password(encrypted_password, key):
    cipher_suite = Fernet(key)
    decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
    return decrypted_password

def encrypt_key(message):
    backend = default_backend()
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(private), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return iv + ciphertext

def decrypt_key(encrypted_message):
    backend = default_backend()
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(private), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_message = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted_message.decode()







def validate_password():
    appdata_path = appdirs.user_data_dir(appname='LemonsPW')
    folder_path = os.path.join(appdata_path, "LemonsPW")
    password_file_path = os.path.join(folder_path, "password.pkl")

    if not os.path.exists(password_file_path):
        print(f"{Fore.YELLOW}[!]{Fore.RED}Password not set. Exiting.")
        sys.exit(1)

    with open(password_file_path, 'rb') as f:
        stored_password = pickle.load(f)
    
    entered_password = getpass("Enter your password: ")

    if entered_password != stored_password:
        print(f"{Fore.RED}Invalid password. Exiting.")
        sys.exit(1)


@app.route('/set_password', methods=['GET', 'POST'])
def set_password():
    appdata_path = appdirs.user_data_dir(appname='LemonsPW')
    folder_path = os.path.join(appdata_path, "LemonsPW")
    password_file_path = os.path.join(folder_path, "password.pkl")

    if os.path.exists(password_file_path):
        return redirect('/login')

    if request.method == 'POST':
        fpassword = request.form['password']
        password = encrypt_password(fpassword, master)
        try:
            os.makedirs(folder_path)
            print(f"{Fore.GREEN}[+]{Fore.CYAN} Folder 'LemonsPW' created successfully.")
            with open(password_file_path, 'wb') as f:
                pickle.dump(password, f)
            print(f"{Fore.GREEN}[+]{Fore.CYAN} Password set successfully.")
            return redirect('/login')
        except OSError as e:
            print(f"{Fore.YELLOW}[!]{Fore.RED}Error: Failed to create folder 'LemonsPW'. Reason: {e}")
            return "Error setting password. Please try again."
        
    return render_template('set_password.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    appdata_path = appdirs.user_data_dir(appname='LemonsPW')
    folder_path = os.path.join(appdata_path, "LemonsPW")
    password_file_path = os.path.join(folder_path, "password.pkl")

    if not os.path.exists(password_file_path):
        return redirect('/set_password')

    if request.method == 'POST':
        entered_password = request.form['password']
        
        with open(password_file_path, 'rb') as f:
            fstored_password = pickle.load(f)
            stored_password = decrypt_password(fstored_password, master)
        if entered_password == stored_password:
            session['logged_in'] = True
            return redirect('/')
        else:
            return "Invalid password"
    return render_template('login.html')


@app.route('/save_credentials', methods=['POST'])
def save_credentials():
    if 'logged_in' not in session:
        return redirect('/login')

    username = request.form['username']
    password = request.form['password']
    website = request.form['website']

    folder_name = f"{username}_{website}"

    appdata_path = appdirs.user_data_dir(appname='LemonsPW')
    folder_path = os.path.join(appdata_path, "LemonsPW")
    folder_full_path = os.path.join(folder_path, folder_name)

    os.makedirs(folder_full_path, exist_ok=True)

    key = generate_key()

    encrypted_password = encrypt_password(password, key)

    with open(os.path.join(folder_full_path, "password.txt"), 'wb') as f:
        f.write(encrypted_password)

    with open(os.path.join(folder_full_path, "key.txt"), 'wb') as f:
        ekey = encrypt_key(f'{str(key)}')
        print (ekey)
        f.write(ekey)


    return redirect('/')


@app.route('/password_list')
def password_list():
    appdata_path = appdirs.user_data_dir(appname='LemonsPW')
    folder_path = os.path.join(appdata_path, "LemonsPW")

    folder_names = os.listdir(folder_path)
    folder_names = [folder_name for folder_name in folder_names if folder_name != "password.pkl"]

    passwords = []
    for folder_name in folder_names:
        website, username = folder_name.split("_")
        passwords.append({"website": website, "username": username})

    return render_template('password_list.html', passwords=passwords)

@app.route('/get_key', methods=['GET'])
def get_key():
    if 'logged_in' not in session:
        return "Unauthorized", 401

    website_username = request.args.get('website')  # Format: website_username

    if '_' not in website_username:
        return "Invalid request", 400

    website, username = website_username.split('_')
    
    folder_path = os.path.join(appdirs.user_data_dir(appname='LemonsPW'), "LemonsPW", website_username)

    key_file_path = os.path.join(folder_path, "key.txt")

    try:
        with open(key_file_path, 'rb') as f:
            key_content = f.read()
            rrkey = decrypt_key(key_content)
            rkey = rrkey[2:-1]
            pw_file_path = os.path.join(folder_path, "password.txt")
            with open(pw_file_path, 'rb') as f:
                pw = f.read()
                rpw = decrypt_password(pw, rkey)
                pyperclip.copy(rpw)
                return "Password copied to clipboard"
    except FileNotFoundError:
        return "Key file not found", 404


@app.route('/')
def index():
    if 'logged_in' not in session:
        return redirect('/login')
    return render_template('index.html')


def start_flask_server():
    app.run()


def open_browser():
    webbrowser.open('http://127.0.0.1:5000')


def start():
    flask_thread = threading.Thread(target=start_flask_server)
    flask_thread.daemon = True
    flask_thread.start()

    webview.create_window('No Title Bar', url='http://127.0.0.1:5000', frameless=True)
    webview.start()


if __name__ == '__main__':
    start()
