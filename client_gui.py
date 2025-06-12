# client_gui.py
import tkinter as tk
import requests
import os
from shared import deserialize_private_key, sign_data
import pyotp

REG_URL = 'http://localhost:5000'  # Registration Server URL
APP_URL = 'http://localhost:6000'  # Application Server URL

class AuthClient:
    def __init__(self, master):
        self.master = master
        master.title("Secure 2FA Login")

        self.label = tk.Label(master, text="User ID:")
        self.label.pack()

        self.entry = tk.Entry(master)
        self.entry.pack()

        self.register_btn = tk.Button(master, text="Register", command=self.register)
        self.register_btn.pack()

        self.login_btn = tk.Button(master, text="Login", command=self.authenticate)
        self.login_btn.pack()

        self.output = tk.Text(master, height=10, width=50)
        self.output.pack()

        self.private_key = None
        self.totp = None

    def register(self):
        user_id = self.entry.get()
        res = requests.post(f'{REG_URL}/register', json={'user_id': user_id}).json()
        self.private_key = deserialize_private_key(res['private_key'])
        self.totp = pyotp.TOTP(res['totp_secret'])

        self.output.insert(tk.END, f"Registered!\nScan this secret with Google Authenticator:\n{res['totp_secret']}\n")

    def authenticate(self):
        user_id = self.entry.get()
        challenge = os.urandom(32)
        signature = sign_data(self.private_key, challenge)
        totp_code = self.totp.now()

        res = requests.post(f'{APP_URL}/authenticate', json={
            'user_id': user_id,
            'challenge': challenge.hex(),
            'signature': signature.hex(),
            'totp_code': totp_code
        }).json()

        self.output.insert(tk.END, f"Auth Result: {res['message']}\n")

if __name__ == "__main__":
    root = tk.Tk()
    client = AuthClient(root)
    root.mainloop()
