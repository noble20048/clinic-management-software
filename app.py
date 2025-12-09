from flask import Flask, request, render_template, redirect, url_for, send_file, session, flash
import sqlite3
from datetime import datetime, timedelta
import pandas as pd
import io
import os
import hashlib
import re

app = Flask(__name__)
DB_FILE = 'patients.db'
app.secret_key = os.environ.get('SECRET_KEY', 'change-me-in-production')

from functools import wraps

def hash_password(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get('admin_id'):
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return wrapped

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_number TEXT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            age TEXT,
            date TEXT NOT NULL,
            time TEXT NOT NULL,
            payment_mode TEXT,
            tests TEXT,
            visit_type TEXT,
            amount REAL DEFAULT 0,
            notes TEXT,
            result_delivered TEXT DEFAULT 'No'
        )
    ''')
    
    # Add token_number column if it doesn't exist (for existing databases)
    c.execute("PRAGMA table_info(visits)")
    columns = [col[1] for col in c.fetchall()]
    if 'token_number' not in columns:
        c.execute("ALTER TABLE visits ADD COLUMN token_number TEXT")
    if 'result_delivered' not in columns:
        c.execute("ALTER TABLE visits ADD COLUMN result_delivered TEXT DEFAULT 'No'")
    
    conn.commit()
    conn.close()

init_db()

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    search = request.form.get('search', '') if request.method == 'POST' else request.args.get('search', '')
    
    if search:
        c.execute("SELECT * FROM visits WHERE name LIKE ? OR phone LIKE ? ORDER BY date DESC, time DESC", 
                  (f'%{search}%', f'%{search}%'))
    else:
        c.execute("SELECT * FROM visits ORDER BY date DESC, time DESC")
    
    visits = c.fetchall()
    conn.close()
    today = datetime.now().strftime('%Y-%m-%d')
    return render_template('index.html', visits=visits, search=search, today=today)

@app.route('/add', methods=['POST'])
@login_required
def add():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        INSERT INTO visits (token_number, name, phone, age, date, time, payment_mode, tests, visit_type, amount, notes, result_delivered)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        request.form.get('token_number', ''),
        request.form['name'],
        request.form['phone'],
        request.form.get('age', ''),
        request.form['date'],
        request.form['time'],
        request.form['payment_mode'],
        request.form.get('tests', ''),
        request.form['visit_type'],
        float(request.form.get('amount', 0) or 0),
        request.form.get('notes', ''),
        request.form.get('result_delivered', 'No')
    ))
    conn.commit()
    conn.close()
    return redirect('/')

@app.route('/toggle-result/<int:id>')
@login_required
def toggle_result(id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT result_delivered FROM visits WHERE id=?", (id,))
    result = c.fetchone()
    if result:
        current = result[0]
        new_value = 'No' if current == 'Yes' else 'Yes'
        c.execute("UPDATE visits SET result_delivered=? WHERE id=?", (new_value, id))
        conn.commit()
    conn.close()
    return redirect(request.referrer or '/')

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM visits WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect('/')


@app.route('/edit/<int:id>', methods=['GET'])
@login_required
def edit(id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM visits WHERE id = ?", (id,))
    visit = c.fetchone()
    conn.close()
    if not visit:
        return redirect('/')
    return render_template('edit.html', visit=visit)


@app.route('/update/<int:id>', methods=['POST'])
@login_required
def update(id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # collect form values
    token_number = request.form.get('token_number', '')
    name = request.form.get('name')
    phone = request.form.get('phone')
    age = request.form.get('age')
    date = request.form.get('date')
    time = request.form.get('time')
    payment_mode = request.form.get('payment_mode')
    tests = request.form.get('tests')
    visit_type = request.form.get('visit_type')
    try:
        amount = float(request.form.get('amount') or 0)
    except ValueError:
        amount = 0
    notes = request.form.get('notes')
    result_delivered = request.form.get('result_delivered', 'No')

    c.execute('''
        UPDATE visits
        SET token_number=?, name=?, phone=?, age=?, date=?, time=?, payment_mode=?, tests=?, visit_type=?, amount=?, notes=?, result_delivered=?
        WHERE id=?
    ''', (token_number, name, phone, age, date, time, payment_mode, tests, visit_type, amount, notes, result_delivered, id))
    conn.commit()
    conn.close()
    return redirect('/')


@app.route('/login', methods=['GET', 'POST'])
def login():
    next_url = request.args.get('next') or url_for('index')
    if request.method == 'POST':
        user = request.form.get('username')
        pwd = request.form.get('password')
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, password FROM admin_users WHERE username = ?", (user,))
        admin = c.fetchone()
        conn.close()
        
        if admin and admin[1] == hash_password(pwd):
            session['admin_id'] = admin[0]
            session['username'] = user
            flash('Logged in successfully', 'success')
            return redirect(request.form.get('next') or next_url)
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html', next=next_url)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        user = request.form.get('username')
        pwd = request.form.get('password')
        pwd_confirm = request.form.get('password_confirm')
        
        if not user or not pwd:
            flash('Username and password are required', 'danger')
            return render_template('signup.html')
        
        if pwd != pwd_confirm:
            flash('Passwords do not match', 'danger')
            return render_template('signup.html')
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO admin_users (username, password) VALUES (?, ?)", 
                     (user, hash_password(pwd)))
            conn.commit()
            conn.close()
            flash('Sign up successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            flash('Username already exists', 'danger')
            return render_template('signup.html')
    
    return render_template('signup.html')


@app.route('/logout')
def logout():
    session.pop('admin_id', None)
    session.pop('username', None)
    flash('Logged out', 'info')
    return redirect(url_for('index'))

@app.route('/report')
@login_required
def report():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    today = datetime.now()
    start = today - timedelta(days=today.weekday())
    end = start + timedelta(days=6)
    c.execute("SELECT * FROM visits WHERE date BETWEEN ? AND ? ORDER BY date, time",
              (start.strftime('%Y-%m-%d'), end.strftime('%Y-%m-%d')))
    visits = c.fetchall()

    # Basic totals
    total = len(visits)
    amount = 0.0

    # Counters
    counts = {
        'consultation': 0,
        'follow_up': 0,
        'certificate': 0,
        'ecg': 0,
    }

    # Payment list (details per visit) and aggregation by payment_mode
    payments = []
    payments_by_mode = {}

    # Tests breakdown: count each test token seen
    test_counts = {}

    for v in visits:
        # schema mapping (after token migration):
        # v[0]=id, v[1]=token_number, v[2]=name, v[3]=phone, v[4]=age,
        # v[5]=date, v[6]=time, v[7]=payment_mode, v[8]=tests, v[9]=visit_type,
        # v[10]=amount, v[11]=notes, v[12]=result_delivered
        # amount
        try:
            amt = v[10]
            if amt is None or amt == '':
                pass
            else:
                amount += float(amt)
        except (ValueError, TypeError):
            pass

        # payments list items
        try:
            payments.append({'id': v[0], 'name': v[2], 'amount': float(v[10]) if v[10] not in (None, '') else 0.0, 'mode': v[7], 'date': v[5]})
        except Exception:
            payments.append({'id': v[0], 'name': v[2], 'amount': 0.0, 'mode': v[7], 'date': v[5]})

        if v[7]:
            payments_by_mode[v[7]] = payments_by_mode.get(v[7], 0.0) + (float(v[10]) if v[10] not in (None, '') else 0.0)

        # visit type counts (normalize)
        vt = (v[9] or '').strip().lower()
        if 'consult' in vt:
            counts['consultation'] += 1
        if 'follow' in vt:
            counts['follow_up'] += 1
        if 'certificate' in vt or 'cert' in vt:
            counts['certificate'] += 1

        # tests parsing
        tests_field = (v[8] or '')
        if tests_field:
            # normalize separators
            tokens = [t.strip().lower() for t in re.split('[,;/\\|]+', tests_field) if t.strip()]
            for t in tokens:
                # increment test token count
                test_counts[t] = test_counts.get(t, 0) + 1
                # special case for ecg
                if 'ecg' in t:
                    counts['ecg'] += 1

    conn.close()

    # Sort payments list by date desc
    payments_sorted = sorted(payments, key=lambda x: x.get('date') or '', reverse=True)

    return render_template('report.html', visits=visits, total=total, amount=amount,
                           start=start.strftime('%d-%m-%Y'), end=end.strftime('%d-%m-%Y'),
                           counts=counts, payments=payments_sorted, payments_by_mode=payments_by_mode, test_counts=test_counts)

@app.route('/export')
@login_required
def export():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM visits ORDER BY date DESC", conn)
    conn.close()
    output = io.BytesIO()
    df.to_csv(output, index=False, encoding='utf-8')
    output.seek(0)
    return send_file(output, mimetype='text/csv', as_attachment=True, download_name=f'clinic_data_{datetime.now().strftime("%Y%m%d")}.csv')

if __name__ == '__main__':
    print("Dad's Clinic Software Started!")
    print("Open in browser: http://localhost:5000")
    print("From mobile: http://YOUR-PC-IP:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)