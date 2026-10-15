import os
import sqlite3
import subprocess
import pickle
import hashlib


# VULNERABILITY 1: Hardcoded credentials
USERNAME = "admin"
PASSWORD = "Admin@12345"


# VULNERABILITY 2: SQL Injection
def get_user(username):
    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()

    cursor.execute(
        "CREATE TABLE users (username TEXT, role TEXT)"
    )
    cursor.execute(
        "INSERT INTO users VALUES ('admin', 'administrator')"
    )

    query = (
        "SELECT * FROM users WHERE username = '"
        + username
        + "'"
    )

    cursor.execute(query)
    result = cursor.fetchall()
    connection.close()

    return result


# VULNERABILITY 3: Command Injection
def check_file(filename):
    command = "ls " + filename
    return subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
    )


# VULNERABILITY 4: Insecure Deserialization
def load_data(serialized_data):
    return pickle.loads(serialized_data)


# VULNERABILITY 5: Weak Cryptographic Hash
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


# VULNERABILITY 6: Path Traversal
def read_file(filename):
    base_directory = "./data"
    file_path = os.path.join(base_directory, filename)

    with open(file_path, "r", encoding="utf-8") as file:
        return file.read()


# VULNERABILITY 7: Dynamic Code Execution
def evaluate_expression(expression):
    return eval(expression)


if __name__ == "__main__":
    print("Vulnerable Security Lab")
    print("This application contains intentional security flaws.")

    print("\nTesting hardcoded credentials:")
    print(f"Username configured: {USERNAME}")

    print("\nTesting SQL injection:")
    print(get_user("admin"))

    print("\nTesting weak hashing:")
    print(hash_password("test-password"))

    print("\nOther vulnerable functions are defined for static analysis.")