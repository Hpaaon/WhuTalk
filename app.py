import os
import sqlite3
import hashlib
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, send_from_directory
from werkzeug.utils import secure_filename
from functools import wraps
from flask_socketio import SocketIO, emit

# ---------- 初始化配置 ----------
app = Flask(__name__)
app.secret_key = 'whutalk-dev-secret-key-change-in-production'  # 用于加密 Session
socketio = SocketIO(app, cors_allowed_origins="*")
DATABASE = 'social.db'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

user_sockets = {}

# ========== M6 实时私信聊天模块 ==========

# ---------- WebSocket 连接处理 ----------
@socketio.on('connect')
def handle_connect():
    if 'user_id' not in session:
        return False
    
    user_id = session['user_id']
    user_sockets[user_id] = request.sid
    print(f"User {user_id} connected via WebSocket")

@socketio.on('disconnect')
def handle_disconnect():
    user_id = session.get('user_id')
    if user_id and user_id in user_sockets:
        del user_sockets[user_id]
        print(f"User {user_id} disconnected from WebSocket")

# ---------- WebSocket 事件：发送私信 ----------
@socketio.on('private_message')
def handle_private_message(data):
    sender_id = session.get('user_id')
    if not sender_id:
        return
    
    receiver_id = data.get('receiver_id')
    content = data.get('content', '').strip()
    
    if not receiver_id or not content:
        return
    
    db = get_db()
    db.execute('INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)',
               (sender_id, receiver_id, content))
    db.commit()
    
    message = db.execute(
        '''SELECT m.id, m.sender_id, m.receiver_id, m.content, m.created_at,
                  u.username, u.profile_pic
           FROM messages m
           JOIN users u ON m.sender_id = u.id
           WHERE m.id = last_insert_rowid()''',
    ).fetchone()
    
    if receiver_id in user_sockets:
        emit('new_message', dict(message), room=user_sockets[receiver_id])
    
    emit('message_sent', dict(message))

# ---------- WebSocket 事件：标记消息已读 ----------
@socketio.on('mark_read')
def handle_mark_read(data):
    user_id = session.get('user_id')
    if not user_id:
        return
    
    sender_id = data.get('sender_id')
    if not sender_id:
        return
    
    db = get_db()
    db.execute('UPDATE messages SET is_read = 1 WHERE receiver_id = ? AND sender_id = ? AND is_read = 0',
               (user_id, sender_id))
    db.commit()
    
    emit('read_confirmed', {'sender_id': sender_id})

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
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES posts (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            is_read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users (id),
            FOREIGN KEY (receiver_id) REFERENCES users (id)
        );
    ''')
    db.commit()
    print("✅ 数据库初始化成功！")

# ---------- 文件上传安全工具 ----------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------- 好友关系工具 ----------
def get_accepted_friend_ids(user_id):
    """获取所有已接受的好友 ID 列表（双向查询）"""
    db = get_db()
    friends = db.execute(
        '''SELECT CASE WHEN user_id = ? THEN friend_id ELSE user_id END AS friend_id
           FROM friendships
           WHERE status = 'accepted' AND (user_id = ? OR friend_id = ?)''',
        (user_id, user_id, user_id)
    ).fetchall()
    return [f['friend_id'] for f in friends]

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

# ---------- 路由：上传文件静态服务 ----------
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ========== M2 个人资料管理模块 ==========

# ---------- 路由：查看个人主页 ----------
@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    db = get_db()
    
    user = db.execute(
        'SELECT id, username, bio, profile_pic, created_at FROM users WHERE id = ?',
        (user_id,)
    ).fetchone()
    
    if not user:
        flash('用户不存在', 'danger')
        return redirect(url_for('timeline'))
    
    posts = db.execute(
        '''SELECT p.id, p.content, p.image_path, p.created_at
           FROM posts p
           WHERE p.user_id = ?
           ORDER BY p.created_at DESC''',
        (user_id,)
    ).fetchall()
    
    is_own_profile = session['user_id'] == user_id
    
    return render_template('profile.html', user=user, posts=posts, is_own_profile=is_own_profile)

# ---------- 路由：编辑个人资料 ----------
@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user_id = session['user_id']
    db = get_db()
    
    user = db.execute('SELECT id, username, bio, profile_pic FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if request.method == 'POST':
        bio = request.form.get('bio', '').strip()
        
        profile_pic = user['profile_pic']
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file.filename and allowed_file(file.filename):
                if profile_pic:
                    old_filename = profile_pic.split('/')[-1]
                    old_path = os.path.join(app.config['UPLOAD_FOLDER'], old_filename)
                    if os.path.exists(old_path):
                        os.remove(old_path)
                
                filename = secure_filename(file.filename)
                ext = filename.rsplit('.', 1)[1].lower()
                new_filename = f"avatar_{user_id}_{secrets.token_hex(8)}.{ext}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
                profile_pic = f"/uploads/{new_filename}"
        
        db.execute('UPDATE users SET bio = ?, profile_pic = ? WHERE id = ?',
                   (bio, profile_pic, user_id))
        db.commit()
        
        flash('✅ 个人资料更新成功！', 'success')
        return redirect(url_for('profile', user_id=user_id))
    
    return render_template('edit_profile.html', user=user)

# ---------- 路由：发布动态 ----------
@app.route('/post', methods=['POST'])
@login_required
def create_post():
    content = request.form.get('content', '').strip()
    
    if not content:
        flash('动态内容不能为空', 'danger')
        return redirect(url_for('timeline'))
    
    user_id = session['user_id']
    image_path = None
    
    if 'image' in request.files:
        file = request.files['image']
        if file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            ext = filename.rsplit('.', 1)[1].lower()
            new_filename = f"{secrets.token_hex(8)}_{os.urandom(4).hex()}.{ext}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
            image_path = f"/uploads/{new_filename}"
    
    db = get_db()
    db.execute('INSERT INTO posts (user_id, content, image_path) VALUES (?, ?, ?)',
               (user_id, content, image_path))
    db.commit()
    
    flash('🎉 动态发布成功！', 'success')
    return redirect(url_for('timeline'))

# ---------- 路由：发表评论 ----------
@app.route('/comment/<int:post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    content = request.form.get('content', '').strip()
    
    if not content:
        flash('评论内容不能为空', 'danger')
        return redirect(url_for('timeline'))
    
    user_id = session['user_id']
    db = get_db()
    
    post = db.execute('SELECT id FROM posts WHERE id = ?', (post_id,)).fetchone()
    if not post:
        flash('动态不存在', 'danger')
        return redirect(url_for('timeline'))
    
    db.execute('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
               (post_id, user_id, content))
    db.commit()
    
    flash('💬 评论成功！', 'success')
    return redirect(url_for('timeline'))

# ---------- 路由：删除动态 ----------
@app.route('/post/delete/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    user_id = session['user_id']
    db = get_db()
    
    post = db.execute('SELECT user_id, image_path FROM posts WHERE id = ?', (post_id,)).fetchone()
    if not post:
        flash('动态不存在', 'danger')
        return redirect(url_for('timeline'))
    
    if post['user_id'] != user_id:
        flash('无权删除该动态', 'danger')
        return redirect(url_for('timeline'))
    
    if post['image_path']:
        image_filename = post['image_path'].split('/')[-1]
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
        if os.path.exists(image_path):
            os.remove(image_path)
    
    db.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()
    
    flash('🗑️ 动态已删除', 'success')
    return redirect(url_for('timeline'))

# ---------- 路由：时间线 ----------
@app.route('/timeline')
@login_required
def timeline():
    user_id = session['user_id']
    friend_ids = get_accepted_friend_ids(user_id)
    
    all_ids = [user_id] + friend_ids
    placeholders = ','.join('?' * len(all_ids))
    
    db = get_db()
    posts = db.execute(
        f'''SELECT p.id, p.user_id, p.content, p.image_path, p.created_at,
                   u.username, u.profile_pic
            FROM posts p
            JOIN users u ON p.user_id = u.id
            WHERE p.user_id IN ({placeholders})
            ORDER BY p.created_at DESC''',
        all_ids
    ).fetchall()
    
    posts_with_comments = []
    for post in posts:
        comments = db.execute(
            '''SELECT c.id, c.user_id, c.content, c.created_at,
                      u.username, u.profile_pic
               FROM comments c
               JOIN users u ON c.user_id = u.id
               WHERE c.post_id = ?
               ORDER BY c.created_at ASC''',
            (post['id'],)
        ).fetchall()
        post_dict = dict(post)
        post_dict['comments'] = comments
        posts_with_comments.append(post_dict)
    
    return render_template('timeline.html', posts=posts_with_comments)

# ========== 好友管理模块 ==========

# ---------- 路由：好友管理主页 ----------
@app.route('/friends', methods=['GET', 'POST'])
@login_required
def friends():
    """
    好友管理主页：
    - GET：展示好友列表、待处理请求、搜索框
    - POST：处理搜索请求
    """
    db = get_db()
    user_id = session['user_id']
    search_results = []
    search_query = ''

    # 处理搜索
    if request.method == 'POST' and 'search' in request.form:
        search_query = request.form.get('search', '').strip()
        if search_query:
            search_results = db.execute(
                '''SELECT id, username, bio, profile_pic, created_at
                   FROM users
                   WHERE username LIKE ? AND id != ?
                   LIMIT 20''',
                (f'%{search_query}%', user_id)
            ).fetchall()

            # 标记每个搜索结果与当前用户的好友关系状态
            enriched_results = []
            for u in search_results:
                rel = db.execute(
                    '''SELECT id, status, user_id, friend_id
                       FROM friendships
                       WHERE (user_id = ? AND friend_id = ?)
                          OR (user_id = ? AND friend_id = ?)''',
                    (user_id, u['id'], u['id'], user_id)
                ).fetchone()
                u_dict = dict(u)
                u_dict['relationship'] = rel
                enriched_results.append(u_dict)
            search_results = enriched_results

    # 获取待处理的好友请求（别人发给我的）
    pending_requests = db.execute(
        '''SELECT f.id AS request_id, f.user_id AS from_id, f.created_at,
                  u.username, u.bio, u.profile_pic
           FROM friendships f
           JOIN users u ON f.user_id = u.id
           WHERE f.friend_id = ? AND f.status = 'pending'
           ORDER BY f.created_at DESC''',
        (user_id,)
    ).fetchall()

    # 获取已接受的好友列表
    accepted_friends = db.execute(
        '''SELECT u.id, u.username, u.bio, u.profile_pic, f.created_at AS friends_since
           FROM friendships f
           JOIN users u ON (CASE WHEN f.user_id = ? THEN f.friend_id ELSE f.user_id END) = u.id
           WHERE f.status = 'accepted'
             AND (f.user_id = ? OR f.friend_id = ?)
           ORDER BY u.username ASC''',
        (user_id, user_id, user_id)
    ).fetchall()

    # 获取我发出的待处理请求
    sent_requests = db.execute(
        '''SELECT f.id AS request_id, f.friend_id AS to_id, f.created_at,
                  u.username, u.bio, u.profile_pic
           FROM friendships f
           JOIN users u ON f.friend_id = u.id
           WHERE f.user_id = ? AND f.status = 'pending'
           ORDER BY f.created_at DESC''',
        (user_id,)
    ).fetchall()

    return render_template('friends.html',
                           search_results=search_results,
                           search_query=search_query,
                           pending_requests=pending_requests,
                           accepted_friends=accepted_friends,
                           sent_requests=sent_requests)


# ---------- 路由：发送好友请求 ----------
@app.route('/friends/request/<int:target_id>', methods=['POST'])
@login_required
def send_friend_request(target_id):
    """向目标用户发送好友请求"""
    user_id = session['user_id']
    db = get_db()

    # 不能添加自己
    if target_id == user_id:
        flash('不能添加自己为好友', 'danger')
        return redirect(url_for('friends'))

    # 目标是否存在
    target = db.execute('SELECT id, username FROM users WHERE id = ?', (target_id,)).fetchone()
    if not target:
        flash('目标用户不存在', 'danger')
        return redirect(url_for('friends'))

    # 是否已存在关系（双向检查）
    existing = db.execute(
        '''SELECT id, status, user_id, friend_id
           FROM friendships
           WHERE (user_id = ? AND friend_id = ?)
              OR (user_id = ? AND friend_id = ?)''',
        (user_id, target_id, target_id, user_id)
    ).fetchone()

    if existing:
        if existing['status'] == 'pending':
            if existing['user_id'] == user_id:
                flash('你已经发送过好友请求了，请等待对方处理', 'warning')
            else:
                # 对方已发来请求 → 直接接受
                db.execute('UPDATE friendships SET status = ? WHERE id = ?',
                           ('accepted', existing['id']))
                db.commit()
                flash(f'你和 {target["username"]} 已经成为好友了！', 'success')
        elif existing['status'] == 'accepted':
            flash('你们已经是好友了', 'info')
        elif existing['status'] == 'rejected':
            # 覆盖旧记录，重新发起
            db.execute('DELETE FROM friendships WHERE id = ?', (existing['id'],))
            db.commit()
            db.execute('INSERT INTO friendships (user_id, friend_id, status) VALUES (?, ?, ?)',
                       (user_id, target_id, 'pending'))
            db.commit()
            flash(f'已重新向 {target["username"]} 发送好友请求', 'success')
        return redirect(url_for('friends'))

    # 无现存关系，直接插入
    db.execute('INSERT INTO friendships (user_id, friend_id, status) VALUES (?, ?, ?)',
               (user_id, target_id, 'pending'))
    db.commit()
    flash(f'已向 {target["username"]} 发送好友请求', 'success')
    return redirect(url_for('friends'))


# ---------- 路由：接受好友请求 ----------
@app.route('/friends/accept/<int:request_id>', methods=['POST'])
@login_required
def accept_friend_request(request_id):
    """接受好友请求（仅接收方可操作）"""
    user_id = session['user_id']
    db = get_db()

    req = db.execute(
        'SELECT * FROM friendships WHERE id = ? AND friend_id = ? AND status = ?',
        (request_id, user_id, 'pending')
    ).fetchone()

    if not req:
        flash('无效的好友请求', 'danger')
        return redirect(url_for('friends'))

    db.execute('UPDATE friendships SET status = ? WHERE id = ?',
               ('accepted', request_id))
    db.commit()

    sender = db.execute('SELECT username FROM users WHERE id = ?', (req['user_id'],)).fetchone()
    flash(f'你和 {sender["username"]} 已经成为好友了！', 'success')
    return redirect(url_for('friends'))


# ---------- 路由：拒绝好友请求 ----------
@app.route('/friends/reject/<int:request_id>', methods=['POST'])
@login_required
def reject_friend_request(request_id):
    """拒绝好友请求（仅接收方可操作）"""
    user_id = session['user_id']
    db = get_db()

    req = db.execute(
        'SELECT * FROM friendships WHERE id = ? AND friend_id = ? AND status = ?',
        (request_id, user_id, 'pending')
    ).fetchone()

    if not req:
        flash('无效的好友请求', 'danger')
        return redirect(url_for('friends'))

    db.execute('UPDATE friendships SET status = ? WHERE id = ?',
               ('rejected', request_id))
    db.commit()

    sender = db.execute('SELECT username FROM users WHERE id = ?', (req['user_id'],)).fetchone()
    flash(f'已拒绝 {sender["username"]} 的好友请求', 'info')
    return redirect(url_for('friends'))


# ---------- 路由：删除好友 ----------
@app.route('/friends/delete/<int:friend_id>', methods=['POST'])
@login_required
def delete_friend(friend_id):
    """删除已建立的好友关系（双向均可操作）"""
    user_id = session['user_id']
    db = get_db()

    # 查找双向的 accepted 关系记录
    friendship = db.execute(
        '''SELECT id, user_id, friend_id FROM friendships
           WHERE status = 'accepted'
             AND ((user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?))''',
        (user_id, friend_id, friend_id, user_id)
    ).fetchone()

    if not friendship:
        flash('未找到该好友关系', 'danger')
        return redirect(url_for('friends'))

    # 获取对方用户名（用于提示）
    friend_username = db.execute(
        'SELECT username FROM users WHERE id = ?', (friend_id,)
    ).fetchone()

    db.execute('DELETE FROM friendships WHERE id = ?', (friendship['id'],))
    db.commit()

    name = friend_username['username'] if friend_username else '该用户'
    flash(f'已删除好友 {name}', 'info')
    return redirect(url_for('friends'))

# ---------- 辅助函数：获取侧边栏所需的数据 (会话列表 + 好友列表) ----------
def get_chat_sidebar_data(db, user_id):
    """提取公共逻辑：获取左侧的会话记录列表，以及弹窗所需的所有好友列表"""
    # 获取历史会话列表
    sessions = db.execute(
        '''SELECT DISTINCT 
               CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END AS other_id,
               MAX(m.created_at) AS last_time
           FROM messages m
           WHERE m.sender_id = ? OR m.receiver_id = ?
           GROUP BY other_id
           ORDER BY last_time DESC''',
        (user_id, user_id, user_id)
    ).fetchall()
    
    chat_sessions = []
    for s in sessions:
        other_user = db.execute('SELECT id, username, profile_pic FROM users WHERE id = ?', (s['other_id'],)).fetchone()
        if other_user:
            unread_count = db.execute(
                'SELECT COUNT(*) AS cnt FROM messages WHERE receiver_id = ? AND sender_id = ? AND is_read = 0',
                (user_id, s['other_id'])
            ).fetchone()['cnt']
            
            last_msg = db.execute(
                '''SELECT content FROM messages
                   WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
                   ORDER BY created_at DESC LIMIT 1''',
                (user_id, s['other_id'], s['other_id'], user_id)
            ).fetchone()
            
            chat_sessions.append({
                'user': other_user,
                'unread_count': unread_count,
                'last_message': last_msg['content'][:30] + '...' if last_msg else '',
                'last_time': s['last_time']
            })
            
    # 获取所有互关好友
    all_friends = db.execute('''
        SELECT u.id, u.username, u.profile_pic 
        FROM users u
        JOIN friendships f ON (u.id = f.friend_id OR u.id = f.user_id)
        WHERE (f.user_id = ? OR f.friend_id = ?) 
          AND u.id != ? 
          AND f.status = 'accepted'
    ''', (user_id, user_id, user_id)).fetchall()

    return chat_sessions, all_friends


# ---------- 路由：聊天会话列表 (默认空白页) ----------
@app.route('/chat')
@login_required
def chat_list():
    user_id = session['user_id']
    db = get_db()
    
    chat_sessions, all_friends = get_chat_sidebar_data(db, user_id)
    
    return render_template('chat.html', 
                           sessions=chat_sessions, 
                           current_user_id=user_id, 
                           all_friends=all_friends)


# ---------- 路由：聊天历史 ----------
@app.route('/chat/<int:friend_id>')
@login_required
def chat_history(friend_id):
    user_id = session['user_id']
    db = get_db()
    
    friend = db.execute('SELECT id, username, profile_pic FROM users WHERE id = ?', (friend_id,)).fetchone()
    if not friend:
        flash('好友不存在', 'danger')
        return redirect(url_for('chat_list'))
    
    chat_sessions, all_friends = get_chat_sidebar_data(db, user_id)
    
    messages = db.execute(
        '''SELECT m.id, m.sender_id, m.receiver_id, m.content, m.is_read, m.created_at,
                  u.username, u.profile_pic
           FROM messages m
           JOIN users u ON m.sender_id = u.id
           WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
           ORDER BY m.created_at ASC''',
        (user_id, friend_id, friend_id, user_id)
    ).fetchall()
    
    db.execute('UPDATE messages SET is_read = 1 WHERE receiver_id = ? AND sender_id = ? AND is_read = 0',
               (user_id, friend_id))
    db.commit()
    
    return render_template('chat.html', 
                           friend=friend, 
                           messages=messages, 
                           sessions=chat_sessions,       
                           current_user_id=user_id, 
                           all_friends=all_friends)      

# ---------- 启动应用 ----------
if __name__ == '__main__':
    with app.app_context():
        init_db()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)