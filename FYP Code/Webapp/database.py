# database.py

import json

# Path to the user database file
DATABASE_FILE = 'users.json'

# Load user data from JSON file
try:
    with open(DATABASE_FILE, 'r') as f:
        users = json.load(f)
except FileNotFoundError:
    users = {}

def save_users():
    with open(DATABASE_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def get_user(username):
    return users.get(username)

def add_user(username, password, is_admin=False):
    if username not in users:
        users[username] = {
            'username': username,
            'password': password,  # Store password in plaintext 
            'is_admin': is_admin,
            'status': 'Approved' if is_admin else 'Pending Approval'
        }
        save_users()  # Save the updated user database
        return True
    return False

def is_approved_user(username):
    user = get_user(username)
    return user and user['status'] == 'Approved'

def get_approved_users():
    return [user for user in users.values() if user['status'] == 'Approved' and not user.get('is_admin', False)]
def validate_user(username, password):
    user = get_user(username)
    if user and user['status'] == 'Approved' and user['password'] == password:
        return True
    return False

def get_pending_users():
    return [user for user in users.values() if user['status'] == 'Pending Approval']

def approve_user(username):
    if username in users:
        users[username]['status'] = 'Approved'
        save_users()  # Save the updated user database
        return True
    return False

def reject_user(username):
    if username in users:
        del users[username]
        save_users()  # Save the updated user database
        return True
    return False

def is_admin(username):
    user = get_user(username)
    return user.get('is_admin', False)  # Return True if user is admin, False otherwise
