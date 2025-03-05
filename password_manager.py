import bcrypt
import json
import os

DB_FILE = "users.json"

def load_users():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r") as file:
        return json.load(file)

def save_users(users):
    with open(DB_FILE, "w") as file:
        json.dump(users, file, indent=4)

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()

def register_user():
    users = load_users()
    username = input("Enter username: ")
    
    if username in users:
        print("Username already exists. Try a different one.")
        return
    
    password = input("Enter password: ")
    hashed_password = hash_password(password)
    
    users[username] = hashed_password
    save_users(users)
    print("User registered successfully!")

def verify_password(stored_hash, password):
    return bcrypt.checkpw(password.encode(), stored_hash.encode())

def login_user():
    users = load_users()
    username = input("Enter username: ")
    
    if username not in users:
        print("User not found!")
        return
    
    password = input("Enter password: ")
    
    if verify_password(users[username], password):
        print("Login successful! Welcome,", username)
    else:
        print("Incorrect password. Access denied.")

def main():
    while True:
        print("\n1. Register User")
        print("2. Login")
        print("3. Exit")
        
        choice = input("Select an option: ")
        
        if choice == "1":
            register_user()
        elif choice == "2":
            login_user()
        elif choice == "3":
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
