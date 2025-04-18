from flask import Flask, render_template, redirect, request, url_for, flash, session, jsonify, flash
import json
import os
import requests
from werkzeug.security import generate_password_hash, check_password_hash

from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.serving import run_simple

# Mount app at /factory
app = Flask(__name__, static_url_path='/factory/static', static_folder='static')
app.config['SECRET_KEY'] = 'your_secret_key'

application = DispatcherMiddleware(Flask('dummy_app'), {
    '/factory': app
})


# Set up paths
alias = "factory"
HOME_DIR = os.path.expanduser("~")
FILES_PATH = os.path.join(HOME_DIR, "script_files", alias)
DATA_DIR = os.path.join(FILES_PATH, "data")
USERS_FILE = os.path.join(DATA_DIR, 'users.json')

USER_PROPERTIES = ["id", "age", "name", "last_name", "phone", "email", "factories"]

FACTORIE_PROPERTIES = ["address", "xxx", "services"]
FACTORY_ADDRESS = ["city", "country", "street", "zip_code", "email", "phone", "website"]
FACTORY_SERVICES = ["cnc", "3d_print", "laser", "assembly", "painting", "welding"]


# Ensure the directory exists
os.makedirs(DATA_DIR, exist_ok=True)

def is_root_registered():
    root = get_root_user()
    return bool(root.get("root_user")) and bool(root.get("password_hash"))


def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as file:
            return json.load(file)
    return []

def save_users(users):
    with open(USERS_FILE, 'w') as file:
        json.dump(users, file, indent=4)

def get_root_user():
    users = load_users()
    return users[0] if users else None

def get_users():
    users = load_users()
    return users[1]["users"] if len(users) > 1 else []

def save_root_user(username, password):
    password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    users = [{"root_user": username, "password_hash": password_hash}, {"users": []}]
    save_users(users)

def save_user(username, password):
    password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    user_data = {
        'user': username,
        'password_hash': password_hash
    }

    for prop in USER_PROPERTIES:
        if prop == "factories":
            user_data[prop] = {}  # <-- Fix this line
        else:
            user_data[prop] = ""

    users = load_users()
    users[1]["users"].append(user_data)
    save_users(users)

def remove_user(username):
    users = load_users()
    users[1]["users"] = [user for user in users[1].get("users", []) if user["user"] != username]
    save_users(users)

@app.route('/')
def index():
    if not is_root_registered():
        return redirect(url_for('register', role='root'))
    return redirect(url_for('login'))

@app.route('/remove_user', methods=['POST'])
def remove_user_route():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    username = request.form['username']
    remove_user(username)
    flash('User removed successfully!', 'success')
    return redirect(url_for('root_dashboard'))

@app.before_request
def check_root_user():
    if not is_root_registered():
        if request.endpoint not in ('register', 'static'):
            return redirect(url_for('register', role='root'))

@app.route('/register/<role>', methods=['GET', 'POST'])
def register(role):
    if role == "root" and is_root_registered():
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
        else:
            if role == "root":
                save_root_user(username, password)
                flash('Root user registered successfully!', 'success')
                return redirect(url_for('login'))
            elif role == "user":
                save_user(username, password)
                flash('User registered successfully!', 'success')
                return redirect(url_for('login'))
    return render_template('register.html', role=role)

@app.route('/login', methods=['GET', 'POST'])
def login():
    root_user = get_root_user()
    users = get_users()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if root_user and username == root_user['root_user'] and check_password_hash(root_user['password_hash'], password):
            session['user_id'] = username
            return redirect(url_for('root_dashboard'))
        for user in users:
            if username == user['user'] and check_password_hash(user['password_hash'], password):
                session['user_id'] = username
                return redirect(url_for('user_dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/root_dashboard')
def root_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    users = get_users()
    return render_template('root_dashboard.html', users=users)

@app.route('/user_dashboard')
def user_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_name = session['user_id']
    users = get_users()
    user_data = next((u for u in users if u['user'] == user_name), {})
    factories = user_data.get('factories', {}) if isinstance(user_data.get('factories'), dict) else {}
    return render_template('user_dashboard.html', user=user_name, factories=factories)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))


@app.route('/add_factory', methods=['GET', 'POST'])
def add_factory():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        factory_name = request.form.get('factory_name')
        address = {key: request.form.get(key, '') for key in FACTORY_ADDRESS}
        services = request.form.getlist('services')

        users = load_users()
        for user in users[1]['users']:
            if user['user'] == session['user_id']:
                # Defensive check
                if not isinstance(user.get('factories'), dict):
                    user['factories'] = {}

                user['factories'][factory_name] = {
                    'address': address,
                    'services': services
                }
                break

        save_users(users)
        flash('Factory added successfully!', 'success')
        return redirect(url_for('user_dashboard'))

    return render_template('add_factory.html', address_fields=FACTORY_ADDRESS, FACTORY_SERVICES=FACTORY_SERVICES)

@app.route('/search_service', methods=['GET', 'POST'])
def search_service():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    results = []
    filters = {}
    selected_service = ""

    if request.method == 'POST':
        selected_service = request.form.get('service', '')
        filters = {field: request.form.get(field, '').strip().lower() for field in FACTORY_ADDRESS}

        users = get_users()
        for user in users:
            user_name = user['user']
            for factory_name, factory in user.get('factories', {}).items():
                # Check if service matches
                if selected_service and selected_service not in factory.get('services', []):
                    continue
                # Check if all address fields match (if filled)
                addr = factory.get('address', {})
                if any(filters[field] and filters[field] not in addr.get(field, '').lower() for field in FACTORY_ADDRESS):
                    continue

                address_display = ', '.join(addr.get(f, '') for f in FACTORY_ADDRESS)
                results.append({
                    "user": user_name,
                    "factory_name": factory_name,
                    "address": address_display,
                    "website": addr.get('website', ''),
                    "email": addr.get('email', ''),
                    "phone": addr.get('phone', '')
                })


    return render_template(
        'search_service.html',
        FACTORY_SERVICES=FACTORY_SERVICES,
        address_fields=FACTORY_ADDRESS,
        filters=filters,
        selected_service=selected_service,
        results=results
    )


def fix_user_data():
    users = load_users()
    changed = False

    # Ensure users list has at least two entries
    if len(users) < 2:
        users = [{"root_user": "", "password_hash": ""}, {"users": []}]
        changed = True

    # Fix users inside second entry
    for user in users[1].get('users', []):
        for prop in USER_PROPERTIES:
            if prop not in user:
                user[prop] = {} if prop == "factories" else ""
                changed = True
            elif prop == "factories" and isinstance(user[prop], str):
                user[prop] = {}
                changed = True

    if changed:
        save_users(users)


fix_user_data()

if __name__ == '__main__':
    run_simple('0.0.0.0', 5000, application, use_reloader=True, use_debugger=True, threaded=True)
