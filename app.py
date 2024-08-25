from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Database setup
def init_db():
    with sqlite3.connect('donations.db') as conn:
        conn.execute('DROP TABLE IF EXISTS users')
        conn.execute('DROP TABLE IF EXISTS donations')
        conn.execute('DROP TABLE IF EXISTS requests')
        
        conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
        ''')
        conn.execute('''
        CREATE TABLE IF NOT EXISTS donations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            item TEXT NOT NULL,
            best_before TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        ''')
        conn.execute('''
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            item TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        ''')

@app.route('/')
def index():
    if 'user_id' in session:
        role = session['role']
        with sqlite3.connect('donations.db') as conn:
            cur = conn.cursor()
            if role == 'Beneficiary':
                cur.execute("SELECT * FROM donations")
            else:
                cur.execute("SELECT * FROM donations WHERE user_id = ?", (session['user_id'],))
            donations = cur.fetchall()
        return render_template('index.html', donations=donations, role=role)
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']
        
        with sqlite3.connect('donations.db') as conn:
            try:
                conn.execute('''
                INSERT INTO users (name, email, password, role)
                VALUES (?, ?, ?, ?)
                ''', (name, email, password, role))
                conn.commit()
                flash('Signup successful! Please login.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Email already exists.', 'danger')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        with sqlite3.connect('donations.db') as conn:
            cur = conn.cursor()
            cur.execute('''
            SELECT * FROM users WHERE email = ?
            ''', (email,))
            user = cur.fetchone()
            if user and check_password_hash(user[3], password):
                session['user_id'] = user[0]
                session['name'] = user[1]
                session['role'] = user[4]
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
            flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/add_donation', methods=['POST'])
def add_donation():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    item = request.form['item']
    best_before = request.form['best_before']

    with sqlite3.connect('donations.db') as conn:
        conn.execute('''
        INSERT INTO donations (user_id, item, best_before)
        VALUES (?, ?, ?)
        ''', (session['user_id'], item, best_before))
        conn.commit()
    return redirect(url_for('index'))

@app.route('/delete_donation/<int:donation_id>')
def delete_donation(donation_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    with sqlite3.connect('donations.db') as conn:
        conn.execute('''
        DELETE FROM donations WHERE id = ? AND user_id = ?
        ''', (donation_id, session['user_id']))
        conn.commit()
    return redirect(url_for('index'))

@app.route('/request_donation', methods=['POST'])
def request_donation():
    if 'user_id' not in session or session['role'] != 'Beneficiary':
        return redirect(url_for('login'))

    item = request.form['item']

    with sqlite3.connect('donations.db') as conn:
        conn.execute('''
        INSERT INTO requests (user_id, item)
        VALUES (?, ?)
        ''', (session['user_id'], item))
        conn.commit()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
