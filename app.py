"""
CWAS - Community Water Access Scheduler
Production-Ready Flask Application
Deployment: Render.com
"""

import os
import sqlite3
import hashlib
import secrets
import json
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for, 
    flash, session, jsonify, g, abort
)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['DATABASE'] = os.environ.get('DATABASE_URL', 'cwas.db')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Madagascar Locations Data
MADAGASCAR_REGIONS = {
    'Analamanga': ['Antananarivo', 'Ankazobe', 'Anjozorobe', 'Manjakandriana'],
    'Vakinankaratra': ['Antsirabe', 'Ambatolampy', 'Betafo', 'Faratsiho'],
    'Itasy': ['Miarinarivo', 'Arivonimamo', 'Soavinandriana'],
    'Bongolava': ['Tsiroanomandidy', 'Fenoarivobe'],
    'Sofia': ['Antsohihy', 'Bealanana', 'Mandritsara'],
    'Boeny': ['Mahajanga', 'Marovoay', 'Ambato-Boeni'],
    'Betsiboka': ['Maevatanana', 'Kandreho', 'Tsaratanana'],
    'Melaky': ['Maintirano', 'Morafenobe', 'Besalampy'],
    'Alaotra-Mangoro': ['Ambatondrazaka', 'Moramanga', 'Andilamena'],
    'Atsinanana': ['Toamasina', 'Brickaville', 'Mahanoro'],
    'Analanjirofo': ['Fenoarivo Atsinanana', 'Mananara Nord', 'Maroantsetra'],
    'Amoron\'i Mania': ['Ambositra', 'Ambatofinandrahana', 'Fandriana'],
    'Haute Matsiatra': ['Fianarantsoa', 'Ambalavao', 'Ambohimahasoa'],
    'Vatovavy-Fitovinany': ['Manakara', 'Mananjary', 'Ifanadiana'],
    'Atsimo-Atsinanana': ['Farafangana', 'Vangaindrano', 'Vondrozo'],
    'Ihorombe': ['Ihosy', 'Ivohibe', 'Iakora'],
    'Menabe': ['Morondava', 'Belo sur Tsiribihina', 'Miandrivazo'],
    'Atsimo-Andrefana': ['Toliara', 'Sakaraha', 'Betioky-Sud'],
    'Androy': ['Ambovombe', 'Bekily', 'Beloha'],
    'Anosy': ['Taolagnaro', 'Amboasary-Sud', 'Betroka'],
    'Diana': ['Antsiranana', 'Ambanja', 'Nosy Be'],
    'Sava': ['Sambava', 'Antalaha', 'Vohemar', 'Andapa']
}

# Water Source Types
WATER_SOURCE_TYPES = [
    {'id': 'borehole', 'name': 'Borehole', 'icon': 'droplet'},
    {'id': 'well', 'name': 'Protected Well', 'icon': 'circle'},
    {'id': 'spring', 'name': 'Natural Spring', 'icon': 'waves'},
    {'id': 'tap', 'name': 'Public Tap Stand', 'icon': 'arrow-down'},
    {'id': 'tank', 'name': 'Water Tank', 'icon': 'box'},
    {'id': 'river', 'name': 'River Point', 'icon': 'trending-right'}
]

# ============== DATABASE FUNCTIONS ==============

def get_db():
    """Get database connection for current request."""
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db

@app.teardown_appcontext
def close_db(exception):
    """Close database connection at end of request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize database with schema."""
    db = get_db()
    
    # Users table
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'coordinator', 'household')),
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            phone TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Households table
    db.execute('''
        CREATE TABLE IF NOT EXISTS households (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            household_name TEXT NOT NULL,
            region TEXT NOT NULL,
            district TEXT NOT NULL,
            village TEXT,
            address TEXT,
            member_count INTEGER DEFAULT 1,
            priority_level INTEGER DEFAULT 3,
            account_balance REAL DEFAULT 0.0,
            total_water_collected REAL DEFAULT 0.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    # Water Sources table
    db.execute('''
        CREATE TABLE IF NOT EXISTS water_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            source_type TEXT NOT NULL,
            region TEXT NOT NULL,
            district TEXT NOT NULL,
            village TEXT,
            latitude REAL,
            longitude REAL,
            capacity_liters INTEGER NOT NULL,
            operating_hours_start TEXT DEFAULT '06:00',
            operating_hours_end TEXT DEFAULT '18:00',
            price_per_liter REAL DEFAULT 0.0,
            health_score INTEGER DEFAULT 100,
            status TEXT DEFAULT 'active' CHECK(status IN ('active', 'maintenance', 'inactive')),
            last_maintenance TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_by INTEGER,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')
    
    # Time Slots table
    db.execute('''
        CREATE TABLE IF NOT EXISTS time_slots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER NOT NULL,
            date DATE NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            max_capacity INTEGER NOT NULL,
            booked_count INTEGER DEFAULT 0,
            is_available INTEGER DEFAULT 1,
            FOREIGN KEY (source_id) REFERENCES water_sources(id) ON DELETE CASCADE,
            UNIQUE(source_id, date, start_time)
        )
    ''')
    
    # Bookings table
    db.execute('''
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            household_id INTEGER NOT NULL,
            source_id INTEGER NOT NULL,
            slot_id INTEGER NOT NULL,
            booking_date DATE NOT NULL,
            requested_liters INTEGER NOT NULL,
            estimated_cost REAL NOT NULL,
            status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'denied', 'completed', 'cancelled', 'no_show')),
            priority_score REAL DEFAULT 0,
            approved_by INTEGER,
            approved_at TIMESTAMP,
            completed_at TIMESTAMP,
            denial_reason TEXT,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (household_id) REFERENCES households(id) ON DELETE CASCADE,
            FOREIGN KEY (source_id) REFERENCES water_sources(id) ON DELETE CASCADE,
            FOREIGN KEY (slot_id) REFERENCES time_slots(id) ON DELETE CASCADE,
            FOREIGN KEY (approved_by) REFERENCES users(id)
        )
    ''')
    
    # Notifications table
    db.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT DEFAULT 'info' CHECK(type IN ('info', 'success', 'warning', 'error')),
            is_read INTEGER DEFAULT 0,
            link TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    # Maintenance Records table
    db.execute('''
        CREATE TABLE IF NOT EXISTS maintenance_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER NOT NULL,
            maintenance_type TEXT NOT NULL,
            description TEXT,
            cost REAL DEFAULT 0,
            performed_by TEXT,
            scheduled_date DATE,
            completed_date DATE,
            status TEXT DEFAULT 'scheduled' CHECK(status IN ('scheduled', 'in_progress', 'completed', 'cancelled')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (source_id) REFERENCES water_sources(id) ON DELETE CASCADE
        )
    ''')
    
    # Chat Messages table
    db.execute('''
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            response TEXT NOT NULL,
            intent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    # Transactions table
    db.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            household_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('deposit', 'payment', 'refund')),
            reference TEXT,
            description TEXT,
            booking_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (household_id) REFERENCES households(id) ON DELETE CASCADE,
            FOREIGN KEY (booking_id) REFERENCES bookings(id)
        )
    ''')
    
    # System Settings table
    db.execute('''
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Anomaly Alerts table
    db.execute('''
        CREATE TABLE IF NOT EXISTS anomaly_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
            description TEXT NOT NULL,
            is_resolved INTEGER DEFAULT 0,
            resolved_by INTEGER,
            resolved_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (source_id) REFERENCES water_sources(id) ON DELETE SET NULL,
            FOREIGN KEY (resolved_by) REFERENCES users(id)
        )
    ''')
    
    db.commit()

def hash_password(password, salt=None):
    """Hash password with salt using PBKDF2."""
    if salt is None:
        salt = secrets.token_hex(32)
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    ).hex()
    return pwd_hash, salt

def verify_password(password, pwd_hash, salt):
    """Verify password against hash."""
    check_hash, _ = hash_password(password, salt)
    return check_hash == pwd_hash

def create_sample_data():
    """Create sample data for demonstration."""
    db = get_db()
    
    # Check if data already exists
    existing = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    if existing > 0:
        return
    
    # Create admin user
    pwd_hash, salt = hash_password('admin123')
    db.execute('''
        INSERT INTO users (username, email, password_hash, salt, role, first_name, last_name, phone)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', ('admin', 'admin@cwas.mg', pwd_hash, salt, 'admin', 'System', 'Administrator', '+261 34 00 000 00'))
    
    # Create coordinator users
    coordinators = [
        ('coord_tana', 'coord.tana@cwas.mg', 'Andry', 'Rakotomalala', '+261 34 11 111 11', 'Analamanga', 'Antananarivo'),
        ('coord_antsirabe', 'coord.antsirabe@cwas.mg', 'Faly', 'Rasoamanana', '+261 34 22 222 22', 'Vakinankaratra', 'Antsirabe'),
        ('coord_mahajanga', 'coord.mahajanga@cwas.mg', 'Hery', 'Randrianarison', '+261 34 33 333 33', 'Boeny', 'Mahajanga')
    ]
    
    for username, email, first, last, phone, region, district in coordinators:
        pwd_hash, salt = hash_password('coord123')
        db.execute('''
            INSERT INTO users (username, email, password_hash, salt, role, first_name, last_name, phone)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (username, email, pwd_hash, salt, 'coordinator', first, last, phone))
    
    # Create household users
    households_data = [
        ('razafy_family', 'razafy@email.mg', 'Jean', 'Razafy', '+261 34 44 444 44', 'Fianakaviana Razafy', 'Analamanga', 'Antananarivo', 'Analakely', 6, 2, 50000),
        ('rabe_house', 'rabe@email.mg', 'Marie', 'Rabe', '+261 34 55 555 55', 'Fianakaviana Rabe', 'Analamanga', 'Antananarivo', 'Isotry', 4, 3, 25000),
        ('rakoto_home', 'rakoto@email.mg', 'Paul', 'Rakoto', '+261 34 66 666 66', 'Fianakaviana Rakoto', 'Vakinankaratra', 'Antsirabe', 'Antsenakely', 5, 2, 35000),
        ('randriana_fam', 'randriana@email.mg', 'Soa', 'Randrianasolo', '+261 34 77 777 77', 'Fianakaviana Randrianasolo', 'Boeny', 'Mahajanga', 'Mahabibo', 7, 1, 75000),
        ('andria_house', 'andria@email.mg', 'Lova', 'Andriamalala', '+261 34 88 888 88', 'Fianakaviana Andriamalala', 'Alaotra-Mangoro', 'Ambatondrazaka', 'Centre', 3, 4, 15000),
        ('tiana_family', 'tiana@email.mg', 'Haja', 'Tiana', '+261 34 99 999 99', 'Fianakaviana Tiana', 'Haute Matsiatra', 'Fianarantsoa', 'Tanana Ambony', 8, 1, 60000),
    ]
    
    for username, email, first, last, phone, hh_name, region, district, village, members, priority, balance in households_data:
        pwd_hash, salt = hash_password('user123')
        cursor = db.execute('''
            INSERT INTO users (username, email, password_hash, salt, role, first_name, last_name, phone)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (username, email, pwd_hash, salt, 'household', first, last, phone))
        user_id = cursor.lastrowid
        
        db.execute('''
            INSERT INTO households (user_id, household_name, region, district, village, member_count, priority_level, account_balance)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, hh_name, region, district, village, members, priority, balance))
    
    # Create water sources
    sources = [
        ('Rano Madio Analakely', 'borehole', 'Analamanga', 'Antananarivo', 'Analakely', -18.9137, 47.5256, 5000, '05:00', '19:00', 5.0, 95),
        ('Dobo Isotry', 'well', 'Analamanga', 'Antananarivo', 'Isotry', -18.9201, 47.5180, 3000, '06:00', '18:00', 3.0, 88),
        ('Loharano Antsirabe', 'spring', 'Vakinankaratra', 'Antsirabe', 'Antsenakely', -19.8659, 47.0333, 4000, '05:30', '17:30', 4.0, 92),
        ('Robine Mahajanga', 'tap', 'Boeny', 'Mahajanga', 'Mahabibo', -15.7167, 46.3167, 6000, '06:00', '20:00', 6.0, 90),
        ('Rezervoara Ambatondrazaka', 'tank', 'Alaotra-Mangoro', 'Ambatondrazaka', 'Centre', -17.8333, 48.4167, 8000, '05:00', '18:00', 4.5, 85),
        ('Loharano Fianarantsoa', 'spring', 'Haute Matsiatra', 'Fianarantsoa', 'Tanana Ambony', -21.4333, 47.0833, 3500, '06:00', '17:00', 3.5, 93),
        ('Rano Toamasina', 'borehole', 'Atsinanana', 'Toamasina', 'Centre', -18.1443, 49.3958, 7000, '05:00', '19:00', 5.5, 91),
        ('Dobo Morondava', 'well', 'Menabe', 'Morondava', 'Centre', -20.2833, 44.2833, 2500, '06:00', '17:00', 3.0, 82),
    ]
    
    admin_id = db.execute('SELECT id FROM users WHERE role = "admin" LIMIT 1').fetchone()[0]
    
    for name, stype, region, district, village, lat, lng, cap, start, end, price, health in sources:
        db.execute('''
            INSERT INTO water_sources (name, source_type, region, district, village, latitude, longitude, 
                capacity_liters, operating_hours_start, operating_hours_end, price_per_liter, health_score, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (name, stype, region, district, village, lat, lng, cap, start, end, price, health, admin_id))
    
    # Generate time slots for next 14 days
    sources_list = db.execute('SELECT id, operating_hours_start, operating_hours_end, capacity_liters FROM water_sources').fetchall()
    
    for source in sources_list:
        start_hour = int(source['operating_hours_start'].split(':')[0])
        end_hour = int(source['operating_hours_end'].split(':')[0])
        max_per_slot = source['capacity_liters'] // ((end_hour - start_hour) * 2)
        
        for day_offset in range(14):
            slot_date = (datetime.now() + timedelta(days=day_offset)).strftime('%Y-%m-%d')
            
            for hour in range(start_hour, end_hour):
                for minute in ['00', '30']:
                    start_time = f'{hour:02d}:{minute}'
                    end_minute = '30' if minute == '00' else '00'
                    end_h = hour if minute == '00' else hour + 1
                    end_time = f'{end_h:02d}:{end_minute}'
                    
                    db.execute('''
                        INSERT OR IGNORE INTO time_slots (source_id, date, start_time, end_time, max_capacity)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (source['id'], slot_date, start_time, end_time, max_per_slot // 10))
    
    # Create some sample bookings
    households_list = db.execute('SELECT id FROM households').fetchall()
    
    today = datetime.now().strftime('%Y-%m-%d')
    yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    
    sample_bookings = [
        (households_list[0]['id'], 1, today, 50, 'pending'),
        (households_list[1]['id'], 1, today, 30, 'approved'),
        (households_list[2]['id'], 3, today, 40, 'pending'),
        (households_list[3]['id'], 4, yesterday, 60, 'completed'),
        (households_list[4]['id'], 5, yesterday, 45, 'completed'),
    ]
    
    for hh_id, source_id, date, liters, status in sample_bookings:
        source = db.execute('SELECT price_per_liter FROM water_sources WHERE id = ?', (source_id,)).fetchone()
        slot = db.execute('SELECT id FROM time_slots WHERE source_id = ? AND date = ? LIMIT 1', (source_id, date)).fetchone()
        if slot:
            cost = liters * source['price_per_liter']
            db.execute('''
                INSERT INTO bookings (household_id, source_id, slot_id, booking_date, requested_liters, estimated_cost, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (hh_id, source_id, slot['id'], date, liters, cost, status))
    
    # Create notifications
    for hh in households_list[:3]:
        user = db.execute('SELECT user_id FROM households WHERE id = ?', (hh['id'],)).fetchone()
        db.execute('''
            INSERT INTO notifications (user_id, title, message, type)
            VALUES (?, ?, ?, ?)
        ''', (user['user_id'], 'Welcome to CWAS', 'Thank you for registering with the Community Water Access Scheduler. You can now book water collection slots.', 'success'))
    
    db.commit()

# ============== AUTHENTICATION ==============

def login_required(f):
    """Decorator to require login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    """Decorator to require specific role(s)."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login'))
            if session.get('role') not in roles:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_current_user():
    """Get current logged in user."""
    if 'user_id' not in session:
        return None
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    return user

def create_notification(user_id, title, message, notif_type='info', link=None):
    """Create a notification for a user."""
    db = get_db()
    db.execute('''
        INSERT INTO notifications (user_id, title, message, type, link)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_id, title, message, notif_type, link))
    db.commit()

# ============== ROUTES ==============

@app.route('/')
def index():
    """Landing page."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('auth/login.html')
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, username)).fetchone()
        
        if user and verify_password(password, user['password_hash'], user['salt']):
            if not user['is_active']:
                flash('Your account has been deactivated. Please contact an administrator.', 'error')
                return render_template('auth/login.html')
            
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['name'] = f"{user['first_name']} {user['last_name']}"
            
            # Update last login
            db.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.now(), user['id']))
            db.commit()
            
            flash(f'Welcome back, {user["first_name"]}!', 'success')
            
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username', '').strip().lower()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        phone = request.form.get('phone', '').strip()
        role = request.form.get('role', 'household')
        
        # Household specific fields
        household_name = request.form.get('household_name', '').strip()
        region = request.form.get('region', '')
        district = request.form.get('district', '')
        village = request.form.get('village', '').strip()
        member_count = request.form.get('member_count', 1, type=int)
        
        # Admin registration code (for security)
        admin_code = request.form.get('admin_code', '').strip()
        
        # Validation
        errors = []
        
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        
        if not email or '@' not in email:
            errors.append('Please enter a valid email address.')
        
        if not password or len(password) < 6:
            errors.append('Password must be at least 6 characters.')
        
        if password != confirm_password:
            errors.append('Passwords do not match.')
        
        if not first_name or not last_name:
            errors.append('Please enter your full name.')
        
        if role == 'household' and not household_name:
            errors.append('Please enter your household name.')
        
        if role in ['admin', 'coordinator']:
            # Verify admin registration code
            valid_codes = {
                'admin': os.environ.get('ADMIN_REG_CODE', 'CWAS_ADMIN_2025'),
                'coordinator': os.environ.get('COORD_REG_CODE', 'CWAS_COORD_2025')
            }
            if admin_code != valid_codes.get(role):
                errors.append(f'Invalid {role} registration code.')
        
        # Check for existing user
        db = get_db()
        existing = db.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email)).fetchone()
        if existing:
            errors.append('Username or email already exists.')
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth/register.html', regions=MADAGASCAR_REGIONS)
        
        # Create user
        pwd_hash, salt = hash_password(password)
        
        try:
            cursor = db.execute('''
                INSERT INTO users (username, email, password_hash, salt, role, first_name, last_name, phone)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (username, email, pwd_hash, salt, role, first_name, last_name, phone))
            
            user_id = cursor.lastrowid
            
            # Create household record if household role
            if role == 'household':
                db.execute('''
                    INSERT INTO households (user_id, household_name, region, district, village, member_count)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (user_id, household_name, region, district, village, member_count))
            
            db.commit()
            
            # Create welcome notification
            create_notification(
                user_id,
                'Welcome to CWAS',
                f'Welcome {first_name}! Your account has been created successfully. You can now access all features of the Community Water Access Scheduler.',
                'success'
            )
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.rollback()
            flash('An error occurred during registration. Please try again.', 'error')
            app.logger.error(f'Registration error: {str(e)}')
    
    return render_template('auth/register.html', regions=MADAGASCAR_REGIONS)

@app.route('/logout')
def logout():
    """User logout."""
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))

# ============== DASHBOARD ==============

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard - routes to role-specific dashboard."""
    role = session.get('role')
    
    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif role == 'coordinator':
        return redirect(url_for('coordinator_dashboard'))
    else:
        return redirect(url_for('household_dashboard'))

@app.route('/dashboard/admin')
@role_required('admin')
def admin_dashboard():
    """Admin dashboard."""
    db = get_db()
    
    # Get statistics
    stats = {
        'total_users': db.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'total_households': db.execute('SELECT COUNT(*) FROM households').fetchone()[0],
        'total_sources': db.execute('SELECT COUNT(*) FROM water_sources').fetchone()[0],
        'active_sources': db.execute('SELECT COUNT(*) FROM water_sources WHERE status = "active"').fetchone()[0],
        'total_bookings': db.execute('SELECT COUNT(*) FROM bookings').fetchone()[0],
        'pending_bookings': db.execute('SELECT COUNT(*) FROM bookings WHERE status = "pending"').fetchone()[0],
        'completed_bookings': db.execute('SELECT COUNT(*) FROM bookings WHERE status = "completed"').fetchone()[0],
        'total_water_distributed': db.execute('SELECT COALESCE(SUM(requested_liters), 0) FROM bookings WHERE status = "completed"').fetchone()[0],
        'total_revenue': db.execute('SELECT COALESCE(SUM(estimated_cost), 0) FROM bookings WHERE status = "completed"').fetchone()[0],
    }
    
    # Recent bookings
    recent_bookings = db.execute('''
        SELECT b.*, h.household_name, ws.name as source_name, u.first_name, u.last_name
        FROM bookings b
        JOIN households h ON b.household_id = h.id
        JOIN water_sources ws ON b.source_id = ws.id
        JOIN users u ON h.user_id = u.id
        ORDER BY b.created_at DESC
        LIMIT 10
    ''').fetchall()
    
    # System alerts
    alerts = db.execute('''
        SELECT * FROM anomaly_alerts 
        WHERE is_resolved = 0 
        ORDER BY created_at DESC 
        LIMIT 5
    ''').fetchall()
    
    # Sources by region
    sources_by_region = db.execute('''
        SELECT region, COUNT(*) as count 
        FROM water_sources 
        GROUP BY region 
        ORDER BY count DESC
    ''').fetchall()
    
    return render_template('dashboard/admin.html', 
                          stats=stats, 
                          recent_bookings=recent_bookings, 
                          alerts=alerts,
                          sources_by_region=sources_by_region)

@app.route('/dashboard/coordinator')
@role_required('coordinator')
def coordinator_dashboard():
    """Coordinator dashboard."""
    db = get_db()
    
    # Get pending bookings
    pending_bookings = db.execute('''
        SELECT b.*, h.household_name, ws.name as source_name, 
               ts.start_time, ts.end_time, u.first_name, u.last_name
        FROM bookings b
        JOIN households h ON b.household_id = h.id
        JOIN water_sources ws ON b.source_id = ws.id
        JOIN time_slots ts ON b.slot_id = ts.id
        JOIN users u ON h.user_id = u.id
        WHERE b.status = 'pending'
        ORDER BY b.booking_date ASC, ts.start_time ASC
    ''').fetchall()
    
    # Today's schedule
    today = datetime.now().strftime('%Y-%m-%d')
    today_bookings = db.execute('''
        SELECT b.*, h.household_name, ws.name as source_name,
               ts.start_time, ts.end_time
        FROM bookings b
        JOIN households h ON b.household_id = h.id
        JOIN water_sources ws ON b.source_id = ws.id
        JOIN time_slots ts ON b.slot_id = ts.id
        WHERE b.booking_date = ? AND b.status = 'approved'
        ORDER BY ts.start_time ASC
    ''', (today,)).fetchall()
    
    # Stats
    stats = {
        'pending_count': len(pending_bookings),
        'today_count': len(today_bookings),
        'sources_count': db.execute('SELECT COUNT(*) FROM water_sources WHERE status = "active"').fetchone()[0],
        'completed_today': db.execute('''
            SELECT COUNT(*) FROM bookings 
            WHERE booking_date = ? AND status = 'completed'
        ''', (today,)).fetchone()[0]
    }
    
    # Water sources
    sources = db.execute('SELECT * FROM water_sources WHERE status = "active" ORDER BY name').fetchall()
    
    return render_template('dashboard/coordinator.html',
                          pending_bookings=pending_bookings,
                          today_bookings=today_bookings,
                          stats=stats,
                          sources=sources)

@app.route('/dashboard/household')
@role_required('household')
def household_dashboard():
    """Household dashboard."""
    db = get_db()
    user_id = session['user_id']
    
    # Get household info
    household = db.execute('''
        SELECT h.*, u.first_name, u.last_name, u.email, u.phone
        FROM households h
        JOIN users u ON h.user_id = u.id
        WHERE h.user_id = ?
    ''', (user_id,)).fetchone()
    
    if not household:
        flash('Household information not found.', 'error')
        return redirect(url_for('index'))
    
    # Get bookings
    bookings = db.execute('''
        SELECT b.*, ws.name as source_name, ts.start_time, ts.end_time
        FROM bookings b
        JOIN water_sources ws ON b.source_id = ws.id
        JOIN time_slots ts ON b.slot_id = ts.id
        WHERE b.household_id = ?
        ORDER BY b.booking_date DESC, ts.start_time DESC
        LIMIT 10
    ''', (household['id'],)).fetchall()
    
    # Stats
    stats = {
        'total_bookings': db.execute('SELECT COUNT(*) FROM bookings WHERE household_id = ?', (household['id'],)).fetchone()[0],
        'pending_bookings': db.execute('SELECT COUNT(*) FROM bookings WHERE household_id = ? AND status = "pending"', (household['id'],)).fetchone()[0],
        'completed_bookings': db.execute('SELECT COUNT(*) FROM bookings WHERE household_id = ? AND status = "completed"', (household['id'],)).fetchone()[0],
        'total_water': db.execute('SELECT COALESCE(SUM(requested_liters), 0) FROM bookings WHERE household_id = ? AND status = "completed"', (household['id'],)).fetchone()[0],
    }
    
    # Upcoming bookings
    today = datetime.now().strftime('%Y-%m-%d')
    upcoming = db.execute('''
        SELECT b.*, ws.name as source_name, ts.start_time, ts.end_time
        FROM bookings b
        JOIN water_sources ws ON b.source_id = ws.id
        JOIN time_slots ts ON b.slot_id = ts.id
        WHERE b.household_id = ? AND b.booking_date >= ? AND b.status IN ('pending', 'approved')
        ORDER BY b.booking_date ASC, ts.start_time ASC
        LIMIT 5
    ''', (household['id'], today)).fetchall()
    
    # Nearby sources
    sources = db.execute('''
        SELECT * FROM water_sources 
        WHERE status = 'active' AND (region = ? OR district = ?)
        ORDER BY name
        LIMIT 5
    ''', (household['region'], household['district'])).fetchall()
    
    return render_template('dashboard/household.html',
                          household=household,
                          bookings=bookings,
                          stats=stats,
                          upcoming=upcoming,
                          sources=sources)

# ============== BOOKINGS ==============

@app.route('/bookings')
@login_required
def bookings_list():
    """List all bookings."""
    db = get_db()
    role = session.get('role')
    
    # Filter parameters
    status_filter = request.args.get('status', '')
    date_filter = request.args.get('date', '')
    source_filter = request.args.get('source', '')
    
    if role == 'household':
        # Get household ID
        household = db.execute('SELECT id FROM households WHERE user_id = ?', (session['user_id'],)).fetchone()
        if not household:
            flash('Household not found.', 'error')
            return redirect(url_for('dashboard'))
        
        query = '''
            SELECT b.*, ws.name as source_name, ts.start_time, ts.end_time,
                   h.household_name
            FROM bookings b
            JOIN water_sources ws ON b.source_id = ws.id
            JOIN time_slots ts ON b.slot_id = ts.id
            JOIN households h ON b.household_id = h.id
            WHERE b.household_id = ?
        '''
        params = [household['id']]
    else:
        query = '''
            SELECT b.*, ws.name as source_name, ts.start_time, ts.end_time,
                   h.household_name, u.first_name, u.last_name
            FROM bookings b
            JOIN water_sources ws ON b.source_id = ws.id
            JOIN time_slots ts ON b.slot_id = ts.id
            JOIN households h ON b.household_id = h.id
            JOIN users u ON h.user_id = u.id
            WHERE 1=1
        '''
        params = []
    
    if status_filter:
        query += ' AND b.status = ?'
        params.append(status_filter)
    
    if date_filter:
        query += ' AND b.booking_date = ?'
        params.append(date_filter)
    
    if source_filter:
        query += ' AND b.source_id = ?'
        params.append(source_filter)
    
    query += ' ORDER BY b.booking_date DESC, ts.start_time DESC'
    
    bookings = db.execute(query, params).fetchall()
    sources = db.execute('SELECT id, name FROM water_sources ORDER BY name').fetchall()
    
    return render_template('bookings/list.html', 
                          bookings=bookings, 
                          sources=sources,
                          status_filter=status_filter,
                          date_filter=date_filter,
                          source_filter=source_filter)

@app.route('/bookings/new', methods=['GET', 'POST'])
@role_required('household')
def new_booking():
    """Create a new booking."""
    db = get_db()
    
    # Get household
    household = db.execute('SELECT * FROM households WHERE user_id = ?', (session['user_id'],)).fetchone()
    
    if not household:
        flash('Household not found.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        source_id = request.form.get('source_id', type=int)
        slot_id = request.form.get('slot_id', type=int)
        booking_date = request.form.get('booking_date')
        requested_liters = request.form.get('requested_liters', type=int)
        notes = request.form.get('notes', '').strip()
        
        # Validation
        if not all([source_id, slot_id, booking_date, requested_liters]):
            flash('Please fill in all required fields.', 'error')
            return redirect(url_for('new_booking'))
        
        if requested_liters < 1 or requested_liters > 200:
            flash('Requested liters must be between 1 and 200.', 'error')
            return redirect(url_for('new_booking'))
        
        # Get source info
        source = db.execute('SELECT * FROM water_sources WHERE id = ? AND status = "active"', (source_id,)).fetchone()
        if not source:
            flash('Invalid water source selected.', 'error')
            return redirect(url_for('new_booking'))
        
        # Check slot availability
        slot = db.execute('''
            SELECT * FROM time_slots 
            WHERE id = ? AND source_id = ? AND date = ? AND is_available = 1
        ''', (slot_id, source_id, booking_date)).fetchone()
        
        if not slot:
            flash('Selected time slot is not available.', 'error')
            return redirect(url_for('new_booking'))
        
        if slot['booked_count'] >= slot['max_capacity']:
            flash('Selected time slot is fully booked.', 'error')
            return redirect(url_for('new_booking'))
        
        # Check for existing booking on same date
        existing = db.execute('''
            SELECT id FROM bookings 
            WHERE household_id = ? AND booking_date = ? AND status IN ('pending', 'approved')
        ''', (household['id'], booking_date)).fetchone()
        
        if existing:
            flash('You already have a booking for this date.', 'error')
            return redirect(url_for('new_booking'))
        
        # Calculate cost
        estimated_cost = requested_liters * source['price_per_liter']
        
        # Check balance
        if household['account_balance'] < estimated_cost:
            flash(f'Insufficient balance. Required: {estimated_cost:,.0f} Ar, Available: {household["account_balance"]:,.0f} Ar', 'error')
            return redirect(url_for('new_booking'))
        
        # Calculate priority score
        priority_score = (6 - household['priority_level']) * 20 + household['member_count'] * 5
        
        try:
            # Create booking
            db.execute('''
                INSERT INTO bookings (household_id, source_id, slot_id, booking_date, 
                    requested_liters, estimated_cost, priority_score, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (household['id'], source_id, slot_id, booking_date, 
                  requested_liters, estimated_cost, priority_score, notes))
            
            # Update slot count
            db.execute('UPDATE time_slots SET booked_count = booked_count + 1 WHERE id = ?', (slot_id,))
            
            db.commit()
            
            flash('Booking created successfully. Awaiting approval.', 'success')
            return redirect(url_for('bookings_list'))
            
        except Exception as e:
            db.rollback()
            flash('An error occurred while creating the booking.', 'error')
            app.logger.error(f'Booking error: {str(e)}')
    
    # GET request - show booking form
    sources = db.execute('''
        SELECT * FROM water_sources 
        WHERE status = 'active'
        ORDER BY name
    ''').fetchall()
    
    # Generate dates for next 14 days
    dates = []
    for i in range(14):
        d = datetime.now() + timedelta(days=i)
        dates.append({
            'value': d.strftime('%Y-%m-%d'),
            'display': d.strftime('%A, %d %B %Y'),
            'short': d.strftime('%a %d')
        })
    
    return render_template('bookings/new.html', 
                          sources=sources, 
                          dates=dates, 
                          household=household)

@app.route('/bookings/<int:booking_id>/approve', methods=['POST'])
@role_required('admin', 'coordinator')
def approve_booking(booking_id):
    """Approve a booking."""
    db = get_db()
    
    booking = db.execute('SELECT * FROM bookings WHERE id = ?', (booking_id,)).fetchone()
    if not booking:
        flash('Booking not found.', 'error')
        return redirect(url_for('bookings_list'))
    
    if booking['status'] != 'pending':
        flash('This booking cannot be approved.', 'error')
        return redirect(url_for('bookings_list'))
    
    try:
        db.execute('''
            UPDATE bookings 
            SET status = 'approved', approved_by = ?, approved_at = ?
            WHERE id = ?
        ''', (session['user_id'], datetime.now(), booking_id))
        
        # Notify household
        household = db.execute('SELECT user_id FROM households WHERE id = ?', (booking['household_id'],)).fetchone()
        create_notification(
            household['user_id'],
            'Booking Approved',
            f'Your booking for {booking["booking_date"]} has been approved.',
            'success',
            url_for('bookings_list')
        )
        
        db.commit()
        flash('Booking approved successfully.', 'success')
        
    except Exception as e:
        db.rollback()
        flash('Error approving booking.', 'error')
        app.logger.error(f'Approve error: {str(e)}')
    
    return redirect(url_for('bookings_list'))

@app.route('/bookings/<int:booking_id>/deny', methods=['POST'])
@role_required('admin', 'coordinator')
def deny_booking(booking_id):
    """Deny a booking."""
    db = get_db()
    
    reason = request.form.get('reason', 'No reason provided')
    
    booking = db.execute('SELECT * FROM bookings WHERE id = ?', (booking_id,)).fetchone()
    if not booking:
        flash('Booking not found.', 'error')
        return redirect(url_for('bookings_list'))
    
    if booking['status'] != 'pending':
        flash('This booking cannot be denied.', 'error')
        return redirect(url_for('bookings_list'))
    
    try:
        db.execute('''
            UPDATE bookings 
            SET status = 'denied', denial_reason = ?, approved_by = ?, approved_at = ?
            WHERE id = ?
        ''', (reason, session['user_id'], datetime.now(), booking_id))
        
        # Release slot
        db.execute('UPDATE time_slots SET booked_count = booked_count - 1 WHERE id = ?', (booking['slot_id'],))
        
        # Notify household
        household = db.execute('SELECT user_id FROM households WHERE id = ?', (booking['household_id'],)).fetchone()
        create_notification(
            household['user_id'],
            'Booking Denied',
            f'Your booking for {booking["booking_date"]} has been denied. Reason: {reason}',
            'error',
            url_for('bookings_list')
        )
        
        db.commit()
        flash('Booking denied.', 'success')
        
    except Exception as e:
        db.rollback()
        flash('Error denying booking.', 'error')
        app.logger.error(f'Deny error: {str(e)}')
    
    return redirect(url_for('bookings_list'))

@app.route('/bookings/<int:booking_id>/complete', methods=['POST'])
@role_required('admin', 'coordinator')
def complete_booking(booking_id):
    """Mark a booking as completed."""
    db = get_db()
    
    booking = db.execute('SELECT * FROM bookings WHERE id = ?', (booking_id,)).fetchone()
    if not booking:
        flash('Booking not found.', 'error')
        return redirect(url_for('bookings_list'))
    
    if booking['status'] != 'approved':
        flash('Only approved bookings can be completed.', 'error')
        return redirect(url_for('bookings_list'))
    
    try:
        # Update booking
        db.execute('''
            UPDATE bookings 
            SET status = 'completed', completed_at = ?
            WHERE id = ?
        ''', (datetime.now(), booking_id))
        
        # Deduct from household balance
        db.execute('''
            UPDATE households 
            SET account_balance = account_balance - ?,
                total_water_collected = total_water_collected + ?
            WHERE id = ?
        ''', (booking['estimated_cost'], booking['requested_liters'], booking['household_id']))
        
        # Create transaction record
        db.execute('''
            INSERT INTO transactions (household_id, amount, type, description, booking_id)
            VALUES (?, ?, 'payment', ?, ?)
        ''', (booking['household_id'], -booking['estimated_cost'], 
              f'Water collection - {booking["requested_liters"]}L', booking_id))
        
        # Notify household
        household = db.execute('SELECT user_id FROM households WHERE id = ?', (booking['household_id'],)).fetchone()
        create_notification(
            household['user_id'],
            'Water Collected',
            f'Your water collection of {booking["requested_liters"]}L has been completed.',
            'success'
        )
        
        db.commit()
        flash('Booking marked as completed.', 'success')
        
    except Exception as e:
        db.rollback()
        flash('Error completing booking.', 'error')
        app.logger.error(f'Complete error: {str(e)}')
    
    return redirect(url_for('bookings_list'))

@app.route('/bookings/<int:booking_id>/cancel', methods=['POST'])
@login_required
def cancel_booking(booking_id):
    """Cancel a booking."""
    db = get_db()
    role = session.get('role')
    
    booking = db.execute('SELECT * FROM bookings WHERE id = ?', (booking_id,)).fetchone()
    if not booking:
        flash('Booking not found.', 'error')
        return redirect(url_for('bookings_list'))
    
    # Check permission
    if role == 'household':
        household = db.execute('SELECT id FROM households WHERE user_id = ?', (session['user_id'],)).fetchone()
        if booking['household_id'] != household['id']:
            flash('You cannot cancel this booking.', 'error')
            return redirect(url_for('bookings_list'))
    
    if booking['status'] not in ['pending', 'approved']:
        flash('This booking cannot be cancelled.', 'error')
        return redirect(url_for('bookings_list'))
    
    try:
        db.execute('UPDATE bookings SET status = "cancelled" WHERE id = ?', (booking_id,))
        db.execute('UPDATE time_slots SET booked_count = booked_count - 1 WHERE id = ?', (booking['slot_id'],))
        db.commit()
        
        flash('Booking cancelled successfully.', 'success')
        
    except Exception as e:
        db.rollback()
        flash('Error cancelling booking.', 'error')
    
    return redirect(url_for('bookings_list'))

# ============== WATER SOURCES ==============

@app.route('/sources')
@login_required
def sources_list():
    """List all water sources."""
    db = get_db()
    
    region_filter = request.args.get('region', '')
    type_filter = request.args.get('type', '')
    status_filter = request.args.get('status', '')
    
    query = 'SELECT * FROM water_sources WHERE 1=1'
    params = []
    
    if region_filter:
        query += ' AND region = ?'
        params.append(region_filter)
    
    if type_filter:
        query += ' AND source_type = ?'
        params.append(type_filter)
    
    if status_filter:
        query += ' AND status = ?'
        params.append(status_filter)
    
    query += ' ORDER BY name'
    
    sources = db.execute(query, params).fetchall()
    
    regions = list(MADAGASCAR_REGIONS.keys())
    
    return render_template('sources/list.html', 
                          sources=sources, 
                          regions=regions,
                          source_types=WATER_SOURCE_TYPES,
                          region_filter=region_filter,
                          type_filter=type_filter,
                          status_filter=status_filter)

@app.route('/sources/new', methods=['GET', 'POST'])
@role_required('admin', 'coordinator')
def new_source():
    """Create a new water source."""
    db = get_db()
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        source_type = request.form.get('source_type', '')
        region = request.form.get('region', '')
        district = request.form.get('district', '')
        village = request.form.get('village', '').strip()
        latitude = request.form.get('latitude', type=float)
        longitude = request.form.get('longitude', type=float)
        capacity = request.form.get('capacity', type=int)
        start_time = request.form.get('operating_hours_start', '06:00')
        end_time = request.form.get('operating_hours_end', '18:00')
        price = request.form.get('price_per_liter', type=float, default=0)
        
        if not all([name, source_type, region, district, capacity]):
            flash('Please fill in all required fields.', 'error')
            return render_template('sources/new.html', regions=MADAGASCAR_REGIONS, source_types=WATER_SOURCE_TYPES)
        
        try:
            db.execute('''
                INSERT INTO water_sources (name, source_type, region, district, village,
                    latitude, longitude, capacity_liters, operating_hours_start, 
                    operating_hours_end, price_per_liter, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (name, source_type, region, district, village, latitude, longitude,
                  capacity, start_time, end_time, price, session['user_id']))
            
            db.commit()
            flash('Water source created successfully.', 'success')
            return redirect(url_for('sources_list'))
            
        except Exception as e:
            db.rollback()
            flash('Error creating water source.', 'error')
            app.logger.error(f'Source creation error: {str(e)}')
    
    return render_template('sources/new.html', regions=MADAGASCAR_REGIONS, source_types=WATER_SOURCE_TYPES)

@app.route('/sources/<int:source_id>')
@login_required
def source_detail(source_id):
    """View water source details."""
    db = get_db()
    
    source = db.execute('SELECT * FROM water_sources WHERE id = ?', (source_id,)).fetchone()
    if not source:
        flash('Water source not found.', 'error')
        return redirect(url_for('sources_list'))
    
    # Get recent bookings
    bookings = db.execute('''
        SELECT b.*, h.household_name, ts.start_time, ts.end_time
        FROM bookings b
        JOIN households h ON b.household_id = h.id
        JOIN time_slots ts ON b.slot_id = ts.id
        WHERE b.source_id = ?
        ORDER BY b.booking_date DESC, ts.start_time DESC
        LIMIT 20
    ''', (source_id,)).fetchall()
    
    # Get maintenance records
    maintenance = db.execute('''
        SELECT * FROM maintenance_records
        WHERE source_id = ?
        ORDER BY scheduled_date DESC
        LIMIT 10
    ''', (source_id,)).fetchall()
    
    # Stats
    stats = {
        'total_bookings': db.execute('SELECT COUNT(*) FROM bookings WHERE source_id = ?', (source_id,)).fetchone()[0],
        'completed_bookings': db.execute('SELECT COUNT(*) FROM bookings WHERE source_id = ? AND status = "completed"', (source_id,)).fetchone()[0],
        'total_water': db.execute('SELECT COALESCE(SUM(requested_liters), 0) FROM bookings WHERE source_id = ? AND status = "completed"', (source_id,)).fetchone()[0],
        'total_revenue': db.execute('SELECT COALESCE(SUM(estimated_cost), 0) FROM bookings WHERE source_id = ? AND status = "completed"', (source_id,)).fetchone()[0],
    }
    
    return render_template('sources/detail.html', 
                          source=source, 
                          bookings=bookings,
                          maintenance=maintenance,
                          stats=stats)

@app.route('/sources/<int:source_id>/edit', methods=['GET', 'POST'])
@role_required('admin', 'coordinator')
def edit_source(source_id):
    """Edit a water source."""
    db = get_db()
    
    source = db.execute('SELECT * FROM water_sources WHERE id = ?', (source_id,)).fetchone()
    if not source:
        flash('Water source not found.', 'error')
        return redirect(url_for('sources_list'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        source_type = request.form.get('source_type', '')
        region = request.form.get('region', '')
        district = request.form.get('district', '')
        village = request.form.get('village', '').strip()
        latitude = request.form.get('latitude', type=float)
        longitude = request.form.get('longitude', type=float)
        capacity = request.form.get('capacity', type=int)
        start_time = request.form.get('operating_hours_start', '06:00')
        end_time = request.form.get('operating_hours_end', '18:00')
        price = request.form.get('price_per_liter', type=float, default=0)
        status = request.form.get('status', 'active')
        health_score = request.form.get('health_score', type=int, default=100)
        
        try:
            db.execute('''
                UPDATE water_sources 
                SET name=?, source_type=?, region=?, district=?, village=?,
                    latitude=?, longitude=?, capacity_liters=?, operating_hours_start=?,
                    operating_hours_end=?, price_per_liter=?, status=?, health_score=?
                WHERE id=?
            ''', (name, source_type, region, district, village, latitude, longitude,
                  capacity, start_time, end_time, price, status, health_score, source_id))
            
            db.commit()
            flash('Water source updated successfully.', 'success')
            return redirect(url_for('source_detail', source_id=source_id))
            
        except Exception as e:
            db.rollback()
            flash('Error updating water source.', 'error')
    
    return render_template('sources/edit.html', 
                          source=source, 
                          regions=MADAGASCAR_REGIONS, 
                          source_types=WATER_SOURCE_TYPES)

@app.route('/sources/<int:source_id>/generate-slots', methods=['POST'])
@role_required('admin', 'coordinator')
def generate_slots(source_id):
    """Generate time slots for a water source."""
    db = get_db()
    
    source = db.execute('SELECT * FROM water_sources WHERE id = ?', (source_id,)).fetchone()
    if not source:
        flash('Water source not found.', 'error')
        return redirect(url_for('sources_list'))
    
    days = request.form.get('days', type=int, default=14)
    
    start_hour = int(source['operating_hours_start'].split(':')[0])
    end_hour = int(source['operating_hours_end'].split(':')[0])
    max_per_slot = max(1, source['capacity_liters'] // ((end_hour - start_hour) * 2) // 10)
    
    slots_created = 0
    
    for day_offset in range(days):
        slot_date = (datetime.now() + timedelta(days=day_offset)).strftime('%Y-%m-%d')
        
        for hour in range(start_hour, end_hour):
            for minute in ['00', '30']:
                start_time = f'{hour:02d}:{minute}'
                end_minute = '30' if minute == '00' else '00'
                end_h = hour if minute == '00' else hour + 1
                end_time = f'{end_h:02d}:{end_minute}'
                
                try:
                    db.execute('''
                        INSERT OR IGNORE INTO time_slots (source_id, date, start_time, end_time, max_capacity)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (source_id, slot_date, start_time, end_time, max_per_slot))
                    slots_created += 1
                except:
                    pass
    
    db.commit()
    flash(f'Generated time slots for {days} days.', 'success')
    
    return redirect(url_for('source_detail', source_id=source_id))

# ============== HOUSEHOLDS ==============

@app.route('/households')
@role_required('admin', 'coordinator')
def households_list():
    """List all households."""
    db = get_db()
    
    region_filter = request.args.get('region', '')
    search = request.args.get('search', '').strip()
    
    query = '''
        SELECT h.*, u.first_name, u.last_name, u.email, u.phone, u.username, u.is_active
        FROM households h
        JOIN users u ON h.user_id = u.id
        WHERE 1=1
    '''
    params = []
    
    if region_filter:
        query += ' AND h.region = ?'
        params.append(region_filter)
    
    if search:
        query += ' AND (h.household_name LIKE ? OR u.first_name LIKE ? OR u.last_name LIKE ?)'
        search_param = f'%{search}%'
        params.extend([search_param, search_param, search_param])
    
    query += ' ORDER BY h.household_name'
    
    households = db.execute(query, params).fetchall()
    
    return render_template('households/list.html', 
                          households=households, 
                          regions=list(MADAGASCAR_REGIONS.keys()),
                          region_filter=region_filter,
                          search=search)

@app.route('/households/<int:household_id>')
@role_required('admin', 'coordinator')
def household_detail(household_id):
    """View household details."""
    db = get_db()
    
    household = db.execute('''
        SELECT h.*, u.first_name, u.last_name, u.email, u.phone, u.username, 
               u.is_active, u.created_at as user_created_at, u.last_login
        FROM households h
        JOIN users u ON h.user_id = u.id
        WHERE h.id = ?
    ''', (household_id,)).fetchone()
    
    if not household:
        flash('Household not found.', 'error')
        return redirect(url_for('households_list'))
    
    # Get bookings
    bookings = db.execute('''
        SELECT b.*, ws.name as source_name, ts.start_time, ts.end_time
        FROM bookings b
        JOIN water_sources ws ON b.source_id = ws.id
        JOIN time_slots ts ON b.slot_id = ts.id
        WHERE b.household_id = ?
        ORDER BY b.booking_date DESC
        LIMIT 20
    ''', (household_id,)).fetchall()
    
    # Get transactions
    transactions = db.execute('''
        SELECT * FROM transactions
        WHERE household_id = ?
        ORDER BY created_at DESC
        LIMIT 20
    ''', (household_id,)).fetchall()
    
    return render_template('households/detail.html',
                          household=household,
                          bookings=bookings,
                          transactions=transactions)

@app.route('/households/<int:household_id>/add-funds', methods=['POST'])
@role_required('admin', 'coordinator')
def add_funds(household_id):
    """Add funds to household account."""
    db = get_db()
    
    amount = request.form.get('amount', type=float)
    reference = request.form.get('reference', '').strip()
    
    if not amount or amount <= 0:
        flash('Please enter a valid amount.', 'error')
        return redirect(url_for('household_detail', household_id=household_id))
    
    try:
        db.execute('UPDATE households SET account_balance = account_balance + ? WHERE id = ?', 
                   (amount, household_id))
        
        db.execute('''
            INSERT INTO transactions (household_id, amount, type, reference, description)
            VALUES (?, ?, 'deposit', ?, 'Account top-up')
        ''', (household_id, amount, reference))
        
        # Notify household
        household = db.execute('SELECT user_id, household_name FROM households WHERE id = ?', (household_id,)).fetchone()
        create_notification(
            household['user_id'],
            'Funds Added',
            f'{amount:,.0f} Ar has been added to your account.',
            'success'
        )
        
        db.commit()
        flash(f'{amount:,.0f} Ar added to account successfully.', 'success')
        
    except Exception as e:
        db.rollback()
        flash('Error adding funds.', 'error')
    
    return redirect(url_for('household_detail', household_id=household_id))

# ============== PROFILE ==============

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile page."""
    db = get_db()
    
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    household = None
    transactions = []
    
    if user['role'] == 'household':
        household = db.execute('SELECT * FROM households WHERE user_id = ?', (session['user_id'],)).fetchone()
        if household:
            transactions = db.execute('''
                SELECT * FROM transactions 
                WHERE household_id = ? 
                ORDER BY created_at DESC 
                LIMIT 10
            ''', (household['id'],)).fetchall()
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_profile':
            first_name = request.form.get('first_name', '').strip()
            last_name = request.form.get('last_name', '').strip()
            phone = request.form.get('phone', '').strip()
            
            try:
                db.execute('''
                    UPDATE users SET first_name = ?, last_name = ?, phone = ?
                    WHERE id = ?
                ''', (first_name, last_name, phone, session['user_id']))
                
                if household:
                    member_count = request.form.get('member_count', type=int, default=1)
                    village = request.form.get('village', '').strip()
                    
                    db.execute('''
                        UPDATE households SET member_count = ?, village = ?
                        WHERE user_id = ?
                    ''', (member_count, village, session['user_id']))
                
                db.commit()
                session['name'] = f'{first_name} {last_name}'
                flash('Profile updated successfully.', 'success')
                
            except Exception as e:
                db.rollback()
                flash('Error updating profile.', 'error')
        
        elif action == 'change_password':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            if not verify_password(current_password, user['password_hash'], user['salt']):
                flash('Current password is incorrect.', 'error')
            elif len(new_password) < 6:
                flash('New password must be at least 6 characters.', 'error')
            elif new_password != confirm_password:
                flash('New passwords do not match.', 'error')
            else:
                pwd_hash, salt = hash_password(new_password)
                db.execute('UPDATE users SET password_hash = ?, salt = ? WHERE id = ?',
                          (pwd_hash, salt, session['user_id']))
                db.commit()
                flash('Password changed successfully.', 'success')
        
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=user, household=household, 
                          transactions=transactions, regions=MADAGASCAR_REGIONS)

# ============== NOTIFICATIONS ==============

@app.route('/notifications')
@login_required
def notifications():
    """View all notifications."""
    db = get_db()
    
    notifs = db.execute('''
        SELECT * FROM notifications 
        WHERE user_id = ? 
        ORDER BY created_at DESC
        LIMIT 50
    ''', (session['user_id'],)).fetchall()
    
    # Mark as read
    db.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ?', (session['user_id'],))
    db.commit()
    
    return render_template('notifications.html', notifications=notifs)

@app.route('/notifications/count')
@login_required
def notification_count():
    """Get unread notification count."""
    db = get_db()
    count = db.execute('''
        SELECT COUNT(*) FROM notifications 
        WHERE user_id = ? AND is_read = 0
    ''', (session['user_id'],)).fetchone()[0]
    
    return jsonify({'count': count})

# ============== AI FEATURES ==============

@app.route('/ai/chatbot')
@login_required
def ai_chatbot():
    """AI Chatbot interface."""
    db = get_db()
    
    # Get chat history
    history = db.execute('''
        SELECT * FROM chat_messages 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 20
    ''', (session['user_id'],)).fetchall()
    
    return render_template('ai/chatbot.html', history=list(reversed(history)))

@app.route('/api/chat', methods=['POST'])
@login_required
def chat_api():
    """Process chatbot message."""
    db = get_db()
    
    message = request.json.get('message', '').strip().lower()
    
    if not message:
        return jsonify({'error': 'Message required'}), 400
    
    # Get user context
    user = get_current_user()
    household = None
    if user['role'] == 'household':
        household = db.execute('SELECT * FROM households WHERE user_id = ?', (user['id'],)).fetchone()
    
    # Intent detection and response generation
    response = ''
    intent = 'general'
    
    # Greeting patterns
    if any(word in message for word in ['hello', 'hi', 'hey', 'salama', 'manahoana', 'good morning', 'good afternoon']):
        intent = 'greeting'
        response = f"Salama! Hello {user['first_name']}! I'm your CWAS assistant. I can help you with:\n\n"
        response += "- Checking water source availability\n"
        response += "- Making and managing bookings\n"
        response += "- Checking your account balance\n"
        response += "- Finding nearby water sources\n"
        response += "- General information about water services\n\n"
        response += "How can I assist you today?"
    
    # Balance inquiry
    elif any(word in message for word in ['balance', 'account', 'money', 'funds', 'vola']):
        intent = 'balance'
        if household:
            response = f"Your current account balance is {household['account_balance']:,.0f} Ar.\n\n"
            response += f"Total water collected: {household['total_water_collected']:,.0f} liters.\n\n"
            if household['account_balance'] < 10000:
                response += "Your balance is running low. Please consider adding funds to continue booking water collection slots."
        else:
            response = "Balance information is available for household accounts."
    
    # Booking related
    elif any(word in message for word in ['book', 'booking', 'reserve', 'schedule', 'slot']):
        intent = 'booking'
        if household:
            pending = db.execute('SELECT COUNT(*) FROM bookings WHERE household_id = ? AND status = "pending"', 
                               (household['id'],)).fetchone()[0]
            approved = db.execute('SELECT COUNT(*) FROM bookings WHERE household_id = ? AND status = "approved"', 
                                (household['id'],)).fetchone()[0]
            
            response = f"You have {pending} pending booking(s) and {approved} approved booking(s).\n\n"
            response += "To make a new booking:\n"
            response += "1. Go to 'New Booking' from your dashboard\n"
            response += "2. Select your preferred date\n"
            response += "3. Choose a water source\n"
            response += "4. Pick an available time slot\n"
            response += "5. Confirm your booking\n\n"
            response += "Would you like me to help you with anything specific?"
        else:
            response = "I can help coordinators and admins manage bookings. What would you like to know?"
    
    # Water sources
    elif any(word in message for word in ['source', 'water', 'location', 'where', 'nearest', 'rano', 'dobo']):
        intent = 'sources'
        sources = db.execute('SELECT * FROM water_sources WHERE status = "active" ORDER BY name LIMIT 5').fetchall()
        
        response = "Here are available water sources:\n\n"
        for s in sources:
            response += f"- {s['name']} ({s['district']}, {s['region']})\n"
            response += f"  Hours: {s['operating_hours_start']} - {s['operating_hours_end']}\n"
            response += f"  Price: {s['price_per_liter']:.1f} Ar/liter\n\n"
        
        response += "You can view more details and availability on the Water Sources page."
    
    # Status inquiry
    elif any(word in message for word in ['status', 'pending', 'approved', 'check']):
        intent = 'status'
        if household:
            recent = db.execute('''
                SELECT b.*, ws.name as source_name 
                FROM bookings b 
                JOIN water_sources ws ON b.source_id = ws.id
                WHERE b.household_id = ? 
                ORDER BY b.created_at DESC LIMIT 3
            ''', (household['id'],)).fetchall()
            
            if recent:
                response = "Your recent bookings:\n\n"
                for b in recent:
                    response += f"- {b['booking_date']} at {b['source_name']}\n"
                    response += f"  Status: {b['status'].upper()}\n"
                    response += f"  Amount: {b['requested_liters']}L ({b['estimated_cost']:,.0f} Ar)\n\n"
            else:
                response = "You don't have any recent bookings."
        else:
            response = "I can help check booking statuses. Please provide more details."
    
    # Help
    elif any(word in message for word in ['help', 'support', 'assist', 'how', 'what']):
        intent = 'help'
        response = "I'm here to help! Here's what I can do:\n\n"
        response += "- Check your account balance and water usage\n"
        response += "- Help you understand the booking process\n"
        response += "- Provide information about water sources\n"
        response += "- Answer questions about CWAS services\n"
        response += "- Guide you through the platform\n\n"
        response += "Just ask me anything related to water access scheduling!"
    
    # Thank you
    elif any(word in message for word in ['thank', 'misaotra', 'thanks']):
        intent = 'thanks'
        response = "Tsara! You're welcome! I'm always here to help. Is there anything else you need assistance with?"
    
    # Default response
    else:
        intent = 'unknown'
        response = "I understand you're asking about: '" + message[:50] + "'\n\n"
        response += "I can help you with:\n"
        response += "- 'balance' - Check your account balance\n"
        response += "- 'book' - Information about making bookings\n"
        response += "- 'sources' - Find water sources\n"
        response += "- 'status' - Check your booking status\n"
        response += "- 'help' - General assistance\n\n"
        response += "Please try one of these topics or rephrase your question."
    
    # Save to history
    db.execute('''
        INSERT INTO chat_messages (user_id, message, response, intent)
        VALUES (?, ?, ?, ?)
    ''', (session['user_id'], request.json.get('message', ''), response, intent))
    db.commit()
    
    return jsonify({
        'response': response,
        'intent': intent
    })

@app.route('/ai/analytics')
@role_required('admin', 'coordinator')
def ai_analytics():
    """AI Analytics dashboard."""
    db = get_db()
    
    # Get booking trends (last 30 days)
    thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
    
    daily_bookings = db.execute('''
        SELECT booking_date, COUNT(*) as count, SUM(requested_liters) as total_liters
        FROM bookings
        WHERE booking_date >= ?
        GROUP BY booking_date
        ORDER BY booking_date
    ''', (thirty_days_ago,)).fetchall()
    
    # Source utilization
    source_stats = db.execute('''
        SELECT ws.name, ws.capacity_liters,
               COUNT(b.id) as booking_count,
               COALESCE(SUM(b.requested_liters), 0) as total_booked
        FROM water_sources ws
        LEFT JOIN bookings b ON ws.id = b.source_id AND b.status IN ('approved', 'completed')
        GROUP BY ws.id
        ORDER BY total_booked DESC
    ''').fetchall()
    
    # Anomaly alerts
    alerts = db.execute('''
        SELECT a.*, ws.name as source_name
        FROM anomaly_alerts a
        LEFT JOIN water_sources ws ON a.source_id = ws.id
        ORDER BY a.created_at DESC
        LIMIT 10
    ''').fetchall()
    
    # Revenue by region
    revenue_by_region = db.execute('''
        SELECT h.region, SUM(b.estimated_cost) as revenue
        FROM bookings b
        JOIN households h ON b.household_id = h.id
        WHERE b.status = 'completed'
        GROUP BY h.region
        ORDER BY revenue DESC
    ''').fetchall()
    
    return render_template('ai/analytics.html',
                          daily_bookings=daily_bookings,
                          source_stats=source_stats,
                          alerts=alerts,
                          revenue_by_region=revenue_by_region)

@app.route('/ai/maintenance')
@role_required('admin', 'coordinator')
def ai_maintenance():
    """Predictive maintenance dashboard."""
    db = get_db()
    
    # Get all sources with health data
    sources = db.execute('''
        SELECT ws.*, 
               COUNT(b.id) as total_bookings,
               COALESCE(SUM(CASE WHEN b.status = 'completed' THEN b.requested_liters ELSE 0 END), 0) as total_distributed
        FROM water_sources ws
        LEFT JOIN bookings b ON ws.id = b.source_id
        GROUP BY ws.id
        ORDER BY ws.health_score ASC
    ''').fetchall()
    
    # Calculate risk scores
    maintenance_predictions = []
    for source in sources:
        # Risk factors
        health_risk = (100 - source['health_score']) / 100
        
        # Days since last maintenance
        if source['last_maintenance']:
            last_maint = datetime.strptime(source['last_maintenance'], '%Y-%m-%d %H:%M:%S')
            days_since = (datetime.now() - last_maint).days
        else:
            days_since = 365  # Assume never maintained
        
        age_risk = min(days_since / 180, 1)  # Max risk after 180 days
        
        # Usage intensity
        usage_risk = min(source['total_distributed'] / (source['capacity_liters'] * 100), 1)
        
        # Combined risk score
        risk_score = (health_risk * 0.4 + age_risk * 0.35 + usage_risk * 0.25) * 100
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = 'critical'
        elif risk_score >= 50:
            risk_level = 'high'
        elif risk_score >= 30:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        maintenance_predictions.append({
            'source': source,
            'risk_score': round(risk_score, 1),
            'risk_level': risk_level,
            'days_since_maintenance': days_since,
            'recommended_action': get_maintenance_recommendation(risk_level, source)
        })
    
    # Sort by risk score
    maintenance_predictions.sort(key=lambda x: x['risk_score'], reverse=True)
    
    # Maintenance records
    recent_maintenance = db.execute('''
        SELECT mr.*, ws.name as source_name
        FROM maintenance_records mr
        JOIN water_sources ws ON mr.source_id = ws.id
        ORDER BY mr.scheduled_date DESC
        LIMIT 10
    ''').fetchall()
    
    return render_template('ai/maintenance.html',
                          predictions=maintenance_predictions,
                          recent_maintenance=recent_maintenance)

def get_maintenance_recommendation(risk_level, source):
    """Generate maintenance recommendation based on risk level."""
    if risk_level == 'critical':
        return f"Immediate inspection required. Schedule maintenance within 7 days."
    elif risk_level == 'high':
        return f"Schedule preventive maintenance within 14 days."
    elif risk_level == 'medium':
        return f"Monitor closely. Plan maintenance within 30 days."
    else:
        return f"Normal operation. Next check in 60 days."

# ============== REPORTS ==============

@app.route('/reports')
@role_required('admin', 'coordinator')
def reports():
    """Reports dashboard."""
    return render_template('reports/index.html')

@app.route('/api/reports/bookings')
@role_required('admin', 'coordinator')
def report_bookings():
    """Get booking statistics."""
    db = get_db()
    
    period = request.args.get('period', '30')
    
    start_date = (datetime.now() - timedelta(days=int(period))).strftime('%Y-%m-%d')
    
    data = db.execute('''
        SELECT booking_date, status, COUNT(*) as count, 
               SUM(requested_liters) as total_liters,
               SUM(estimated_cost) as total_cost
        FROM bookings
        WHERE booking_date >= ?
        GROUP BY booking_date, status
        ORDER BY booking_date
    ''', (start_date,)).fetchall()
    
    return jsonify([dict(row) for row in data])

@app.route('/api/reports/revenue')
@role_required('admin', 'coordinator')
def report_revenue():
    """Get revenue statistics."""
    db = get_db()
    
    period = request.args.get('period', '30')
    start_date = (datetime.now() - timedelta(days=int(period))).strftime('%Y-%m-%d')
    
    data = db.execute('''
        SELECT DATE(created_at) as date, SUM(amount) as total
        FROM transactions
        WHERE type = 'payment' AND DATE(created_at) >= ?
        GROUP BY DATE(created_at)
        ORDER BY date
    ''', (start_date,)).fetchall()
    
    return jsonify([dict(row) for row in data])

# ============== API ENDPOINTS ==============

@app.route('/api/slots/<date>/<int:source_id>')
@login_required
def get_slots(date, source_id):
    """Get available slots for a date and source."""
    db = get_db()
    
    slots = db.execute('''
        SELECT * FROM time_slots
        WHERE source_id = ? AND date = ? AND is_available = 1
        AND booked_count < max_capacity
        ORDER BY start_time
    ''', (source_id, date)).fetchall()
    
    return jsonify([dict(s) for s in slots])

@app.route('/api/districts/<region>')
def get_districts(region):
    """Get districts for a region."""
    districts = MADAGASCAR_REGIONS.get(region, [])
    return jsonify(districts)

# ============== ERROR HANDLERS ==============

@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('errors/500.html'), 500

# ============== CONTEXT PROCESSORS ==============

@app.context_processor
def utility_processor():
    """Add utility functions to templates."""
    def get_unread_count():
        if 'user_id' not in session:
            return 0
        db = get_db()
        return db.execute('''
            SELECT COUNT(*) FROM notifications 
            WHERE user_id = ? AND is_read = 0
        ''', (session['user_id'],)).fetchone()[0]
    
    return {
        'unread_count': get_unread_count,
        'now': datetime.now
    }

# ============== FOOTER & PUBLIC PAGES ==============

@app.route('/help')
def help_page():
    """Help center page."""
    return render_template('pages/help.html')


@app.route('/faq')
def faq():
    """FAQ page."""
    return render_template('pages/faq.html')


@app.route('/api-docs')
def api_docs():
    """API documentation page."""
    return render_template('pages/api.html')


@app.route('/status')
def status_page():
    """System status page."""
    return render_template('pages/status.html')


@app.route('/support', methods=['GET', 'POST'])
def support_page():
    """Support contact page."""
    if request.method == 'POST':
        flash('Your message has been sent. We will get back to you soon.', 'success')
        return redirect(url_for('support_page'))
    return render_template('pages/support.html')


@app.route('/about')
def about():
    """About page."""
    return render_template('pages/about.html')


@app.route('/contact', methods=['GET'])
def contact():
    """Contact page."""
    return render_template('pages/contact.html')


@app.route('/contact', methods=['POST'])
def contact_submit():
    """Handle contact form submission."""
    # Optionally capture form fields; keep behaviour consistent
    flash('Thank you for your message! We will get back to you soon.', 'success')
    return redirect(url_for('contact'))


@app.route('/privacy')
def privacy():
    return render_template('pages/privacy.html')


@app.route('/terms')
def terms():
    return render_template('pages/terms.html')


# ============== MAIN ==============

if __name__ == '__main__':
    with app.app_context():
        init_db()
        create_sample_data()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('DEBUG', 'False').lower() == 'true')
