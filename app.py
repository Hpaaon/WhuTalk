import os
import sqlite3
import hashlib
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from functools import wraps

# ---------- 初始化配置 ----------
app = Flask(__name__)
app.secret_key = 'whutalk-dev-secret-key-change-in-production'  # 用于加密 Session
DATABASE = 'social.db'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ---------- 数据库操作工具 ----------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """初始化数据库表结构（如果不存在）"""
    db = get_db()
    cursor = db.cursor()
    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            bio TEXT,
            profile_pic TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            image_path TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            friend_id INTEGER NOT NULL,
            status TEXT CHECK(status IN ('pending', 'accepted', 'rejected')) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (friend_id) REFERENCES users (id),
            UNIQUE(user_id, friend_id)
        );
    ''')
    db.commit()
    print("✅ 数据库初始化成功！")

# ---------- 密码加密工具（M5：基础设施） ----------
def hash_password(password):
    """生成随机盐并返回 盐:哈希值 格式的字符串"""
    salt = secrets.token_hex(16)
    hash_value = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{hash_value}"

def check_password(password_hash, password):
    """验证密码是否匹配存储的哈希值"""
    salt, hash_value = password_hash.split(':')
    return hashlib.sha256((salt + password).encode()).hexdigest() == hash_value

# ---------- 登录鉴权装饰器 ----------
def login_required(view_func):
    """未登录用户自动重定向到登录页"""
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    return wrapper

# ---------- 路由：首页（重定向到时间线） ----------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('timeline'))  # 时间线路由稍后实现，先占位
    return redirect(url_for('login'))

# ---------- 路由：注册 ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        bio = request.form.get('bio', '').strip()
        
        # 基础校验
        if not username or not password:
            flash('用户名和密码不能为空', 'danger')
            return render_template('register.html')
        
        db = get_db()
        # 检查用户名是否已被占用
        existing = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing:
            flash('用户名已存在，请换一个', 'danger')
            return render_template('register.html')
        
        # 密码加密并入库
        hashed = hash_password(password)
        db.execute('INSERT INTO users (username, password_hash, bio) VALUES (?, ?, ?)',
                   (username, hashed, bio))
        db.commit()
        flash('🎉 注册成功！请登录', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# ---------- 路由：登录 ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and check_password(user['password_hash'], password):
            # 登录成功：写入 Session
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash(f'👋 欢迎回来，{user["username"]}！', 'success')
            return redirect(url_for('timeline'))  # 暂重定向到时间线（稍后实现）
        else:
            flash('用户名或密码错误', 'danger')
    
    return render_template('login.html')

# ---------- 路由：登出 ----------
@app.route('/logout')
def logout():
    session.clear()
    flash('已安全退出', 'info')
    return redirect(url_for('login'))

# ---------- 路由：时间线（占位，等下一阶段实现） ----------
@app.route('/timeline')
@login_required
def timeline():
    # 临时占位，后面会被替换为真正的动态列表
    return "<h1>时间线页面（待实现）</h1><p>你已经登录了，这里是动态流的占位页面。</p>"

# ---------- 启动应用 ----------
if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)