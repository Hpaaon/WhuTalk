import os
import sqlite3
from flask import Flask, g

# ---------- 初始化配置 ----------
app = Flask(__name__)
app.secret_key = 'whutalk-dev-secret-key-change-in-production'  # Session加密密钥

DATABASE = 'social.db'          # SQLite 数据库文件名
UPLOAD_FOLDER = 'uploads'       # 图片上传文件夹
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 确保上传文件夹存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ---------- 数据库操作工具 ----------
def get_db():
    """获取当前请求的数据库连接"""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 让查询结果像字典一样操作
    return db

@app.teardown_appcontext
def close_connection(exception):
    """请求结束后自动关闭数据库连接"""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """初始化数据库：创建我们定义好的三张表（如果不存在）"""
    db = get_db()
    cursor = db.cursor()
    
    # 完全按照需求文档的数据字典创建（users, posts, friendships）
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
    print("✅ 数据库初始化成功！已创建 users, posts, friendships 三张表。")

# ---------- 测试路由 ----------
@app.route('/')
def hello():
    return "<h1>✅ WhuTalk 环境搭建成功！</h1><p>数据库已就绪，可以开始编写业务代码了。</p>"

# ---------- 启动应用 ----------
if __name__ == '__main__':
    # 注意：这句代码必须放在 app.run() 之前，且需要在应用上下文中执行
    with app.app_context():
        init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)