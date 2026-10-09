import hashlib
import pickle
import random
import sqlite3
import subprocess
import ssl
import urllib.request
from pathlib import Path


# 1. Code injection
def calculate(user_input):
    return eval(user_input)


# 2. Command injection
def list_files(filename):
    command = f"dir {filename}"
    return subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True
    )


# 3. SQL injection
def get_user(connection, username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return connection.execute(query).fetchall()


# 4. Hardcoded secret (fake training value)
API_KEY = "FAKE_TRAINING_API_KEY_123456"


# 5. Weak cryptographic hash
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


# 6. Insecure random token generation
def generate_token():
    return str(random.randint(100000, 999999))


# 7. Path traversal
def read_file(filename):
    return Path("files", filename).read_text()


# 8. Unsafe deserialization
def load_data(data):
    return pickle.loads(data)


# 9. TLS certificate verification disabled
def fetch_url(url):
    context = ssl._create_unverified_context()

    with urllib.request.urlopen(
        url, context=context, timeout=5
    ) as response:
        return response.read()


# 10. Sensitive information in logs
def login(username, password):
    print(f"Login attempt: {username}, password={password}")


# 11. Broad exception handling
def load_config(filename):
    try:
        return Path(filename).read_text()
    except Exception:
        return None


if __name__ == "__main__":
    print("Vulnerable application loaded.")
    print("Training lab only — do not use with real data.")