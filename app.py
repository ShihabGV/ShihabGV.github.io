from flask import Flask, render_template, request, redirect, url_for, session, g
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps
from googleapiclient.discovery import build

app = Flask(__name__)
app.secret_key = 'shihab_GV'  # Change this to a secure secret key

# Replace with your API key and channel ID
API_KEY = 'AIzaSyCB8RQC_0i_iPHsF5YsdjNYP2Kd_AWheXs'
CHANNEL_ID = 'UCxkLXxSKPHIdQodlNhGVX5g'  # Replace with your channel ID

def get_channel_subscribers(api_key, channel_id):
    youtube = build('youtube', 'v3', developerKey=api_key)
    request = youtube.channels().list(part='statistics', id=channel_id)
    response = request.execute()
    subscribers = response['items'][0]['statistics']['subscriberCount']
    return int(subscribers)

def init_db():
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        # Create table if not exists
        cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                          (id INTEGER PRIMARY KEY, 
                           username TEXT UNIQUE, 
                           password TEXT,
                           role TEXT DEFAULT 'user')''')
        # Add role column if it doesn't exist
        cursor.execute('PRAGMA table_info(users)')
        columns = [column[1] for column in cursor.fetchall()]
        if 'role' not in columns:
            cursor.execute('ALTER TABLE users ADD COLUMN role TEXT DEFAULT "user"')
        # Ensure admin user exists
        cursor.execute('''INSERT OR IGNORE INTO users (username, password, role) 
                          VALUES (?, ?, ?)''', 
                       ('admin', generate_password_hash('al@bri4344', method='pbkdf2:sha256'), 'admin'))
        conn.commit()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session or session.get('role') != 'admin':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def load_logged_in_user():
    user = session.get('user')
    if user:
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (user,))
            g.user = cursor.fetchone()

@app.route('/')
@login_required
def home():
    return render_template('index.html', title='Home')

@app.route('/about')
@login_required
def about():
    subscriber_count = get_channel_subscribers(API_KEY, CHANNEL_ID)
    return render_template('about.html', title='About Us', subscriber_count=subscriber_count)

@app.route('/services')
@login_required
def services():
    return render_template('services.html', title='Our Services')

@app.route('/contact')
@login_required
def contact():
    return render_template('contact.html', title='Contact Us')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username and password:
            with sqlite3.connect('users.db') as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
                user = cursor.fetchone()
            if user and check_password_hash(user[2], password):
                session['user'] = username
                session['role'] = user[3]
                return redirect(url_for('home'))
            else:
                return 'Invalid credentials', 401
    return render_template('login.html', title='Login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username and password:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            try:
                with sqlite3.connect('users.db') as conn:
                    cursor = conn.cursor()
                    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                                   (username, hashed_password))
                    conn.commit()
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                return 'Username already exists', 400
    return render_template('register.html', title='Register')

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, role FROM users')
        users = cursor.fetchall()
    return render_template('admin_dashboard.html', title='Admin Dashboard', users=users)

@app.route('/admin/grant/<int:user_id>')
@admin_required
def grant_access(user_id):
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if user and user[0] != 'admin':  # Ensure admin cannot be modified
            cursor.execute('UPDATE users SET role = ? WHERE id = ?', ('admin', user_id))
            conn.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/revoke/<int:user_id>')
@admin_required
def revoke_access(user_id):
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if user and user[0] != 'admin':  # Ensure admin cannot be modified
            cursor.execute('UPDATE users SET role = ? WHERE id = ?', ('user', user_id))
            conn.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete/<int:user_id>')
@admin_required
def delete_user(user_id):
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if user and user[0] != 'admin':  # Ensure admin cannot be deleted
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=4344, debug=True)
