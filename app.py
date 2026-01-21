from flask import Flask, request, jsonify
import sqlite3
import jwt
import bcrypt
from datetime import datetime, timedelta
import json
from functools import wraps

app = Flask(__name__)
app.secret_key = 'simple-secret-key-for-dev'


# ========== БАЗА ДАННЫХ ==========
def init_db():
    """Создаем простую БД"""
    conn = sqlite3.connect('simple_auth.db')
    c = conn.cursor()

    # Таблица пользователей
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        first_name TEXT,
        last_name TEXT,
        is_active BOOLEAN DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Таблица токенов (для черного списка)
    c.execute('''
    CREATE TABLE IF NOT EXISTS tokens (
        token TEXT PRIMARY KEY,
        user_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    conn.commit()
    conn.close()


# ========== ХЕЛПЕРЫ ==========
def hash_password(password):
    """Хеширование пароля"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(password, hashed):
    """Проверка пароля"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))


def create_token(user_id, email):
    """Создание JWT токена"""
    payload = {
        'user_id': user_id,
        'email': email,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, app.secret_key, algorithm='HS256')


def verify_token(token):
    """Проверка токена"""
    try:
        # Проверяем в черном списке
        conn = sqlite3.connect('simple_auth.db')
        c = conn.cursor()
        c.execute('SELECT 1 FROM tokens WHERE token = ?', (token,))
        if c.fetchone():
            conn.close()
            return None

        # Декодируем токен
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        conn.close()
        return payload
    except:
        return None


def add_to_blacklist(token, user_id):
    """Добавляем токен в черный список"""
    conn = sqlite3.connect('simple_auth.db')
    c = conn.cursor()
    c.execute('INSERT OR IGNORE INTO tokens (token, user_id) VALUES (?, ?)', (token, user_id))
    conn.commit()
    conn.close()


def get_user_by_email(email):
    """Получение пользователя по email"""
    conn = sqlite3.connect('simple_auth.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE email = ? AND is_active = 1', (email,))
    user = c.fetchone()
    conn.close()
    return user


# ========== ДЕКОРАТОРЫ ==========
def login_required(f):
    """Декоратор для проверки аутентификации"""

    @wraps(f)  # Важно! Сохраняем оригинальное имя функции
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Требуется авторизация'}), 401

        token = auth_header.split(' ')[1]
        payload = verify_token(token)

        if not payload:
            return jsonify({'error': 'Неверный или истекший токен'}), 401

        request.user_id = payload['user_id']
        request.user_email = payload['email']

        return f(*args, **kwargs)

    return decorated_function


# ========== API ЭНДПОИНТЫ ==========

@app.route('/api/register', methods=['POST'])
def register():
    """Регистрация пользователя"""
    try:
        data = request.get_json()

        # Проверяем обязательные поля
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email и пароль обязательны'}), 400

        if data.get('password') != data.get('password_confirm'):
            return jsonify({'error': 'Пароли не совпадают'}), 400

        # Проверяем, существует ли пользователь
        if get_user_by_email(data['email']):
            return jsonify({'error': 'Пользователь уже существует'}), 400

        # Создаем пользователя
        conn = sqlite3.connect('simple_auth.db')
        c = conn.cursor()
        c.execute('''
            INSERT INTO users (email, password, first_name, last_name)
            VALUES (?, ?, ?, ?)
        ''', (
            data['email'],
            hash_password(data['password']),
            data.get('first_name', ''),
            data.get('last_name', '')
        ))
        user_id = c.lastrowid
        conn.commit()
        conn.close()

        return jsonify({
            'message': 'Регистрация успешна',
            'user_id': user_id
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/login', methods=['POST'])
def login():
    """Вход в систему"""
    try:
        data = request.get_json()

        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email и пароль обязательны'}), 400

        # Ищем пользователя
        user = get_user_by_email(data['email'])
        if not user:
            return jsonify({'error': 'Неверный email или пароль'}), 401

        # Проверяем пароль
        user_id, email, password_hash, first_name, last_name, is_active, created_at = user
        if not check_password(data['password'], password_hash):
            return jsonify({'error': 'Неверный email или пароль'}), 401

        # Создаем токен
        token = create_token(user_id, email)

        return jsonify({
            'token': token,
            'user': {
                'id': user_id,
                'email': email,
                'first_name': first_name,
                'last_name': last_name
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    """Выход из системы"""
    try:
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(' ')[1]

        add_to_blacklist(token, request.user_id)

        return jsonify({'message': 'Выход выполнен успешно'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile():
    """Получение профиля"""
    conn = sqlite3.connect('simple_auth.db')
    c = conn.cursor()
    c.execute('SELECT id, email, first_name, last_name, created_at FROM users WHERE id = ?', (request.user_id,))
    user = c.fetchone()
    conn.close()

    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404

    return jsonify({
        'id': user[0],
        'email': user[1],
        'first_name': user[2],
        'last_name': user[3],
        'created_at': user[4]
    })


@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    """Обновление профиля"""
    try:
        data = request.get_json()

        conn = sqlite3.connect('simple_auth.db')
        c = conn.cursor()

        updates = []
        params = []

        if 'first_name' in data:
            updates.append('first_name = ?')
            params.append(data['first_name'])

        if 'last_name' in data:
            updates.append('last_name = ?')
            params.append(data['last_name'])

        if not updates:
            return jsonify({'error': 'Нет данных для обновления'}), 400

        params.append(request.user_id)
        query = f'UPDATE users SET {", ".join(updates)} WHERE id = ?'

        c.execute(query, params)
        conn.commit()
        conn.close()

        return jsonify({'message': 'Профиль обновлен'})

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/profile/delete', methods=['POST'])
@login_required
def delete_account():
    """Мягкое удаление аккаунта"""
    try:
        conn = sqlite3.connect('simple_auth.db')
        c = conn.cursor()

        # Мягкое удаление (is_active = 0)
        c.execute('UPDATE users SET is_active = 0 WHERE id = ?', (request.user_id,))

        # Добавляем токен в черный список
        auth_header = request.headers.get('Authorization')
        if auth_header:
            token = auth_header.split(' ')[1]
            add_to_blacklist(token, request.user_id)

        conn.commit()
        conn.close()

        return jsonify({'message': 'Аккаунт удален'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ========== ДЕМО-РЕСУРСЫ ==========

@app.route('/api/products', methods=['GET'])
@login_required
def get_products():
    """Демо: получение товаров"""
    # Простая проверка прав - у всех есть доступ
    products = [
        {"id": 1, "name": "Ноутбук", "price": 50000, "owner": request.user_id},
        {"id": 2, "name": "Смартфон", "price": 30000, "owner": 999},
    ]
    return jsonify({'products': products})


@app.route('/api/orders', methods=['GET'])
@login_required
def get_orders():
    """Демо: получение заказов"""
    orders = [
        {"id": 1, "product": "Ноутбук", "status": "доставлен", "user_id": request.user_id},
        {"id": 2, "product": "Смартфон", "status": "в обработке", "user_id": 999},
    ]
    return jsonify({'orders': orders})


@app.route('/api/admin/users', methods=['GET'])
@login_required
def get_users():
    """Демо: админский эндпоинт (доступ только админу)"""
    # Простая проверка на админа
    if request.user_email != 'admin@example.com':
        return jsonify({'error': 'Доступ запрещен'}), 403

    conn = sqlite3.connect('simple_auth.db')
    c = conn.cursor()
    c.execute('SELECT id, email, first_name, last_name, is_active FROM users')
    users = c.fetchall()
    conn.close()

    users_list = []
    for user in users:
        users_list.append({
            'id': user[0],
            'email': user[1],
            'first_name': user[2],
            'last_name': user[3],
            'is_active': bool(user[4])
        })

    return jsonify({'users': users_list})


# ========== ЗАПУСК ==========

if __name__ == '__main__':
    print("=" * 50)
    print("ПРОСТАЯ СИСТЕМА АУТЕНТИФИКАЦИИ")
    print("=" * 50)

    # Инициализируем БД
    init_db()

    # Создаем тестового пользователя
    conn = sqlite3.connect('simple_auth.db')
    c = conn.cursor()

    # Проверяем, есть ли уже тестовые пользователи
    c.execute('SELECT 1 FROM users WHERE email = ?', ('admin@example.com',))
    if not c.fetchone():
        c.execute('INSERT INTO users (email, password, first_name, last_name) VALUES (?, ?, ?, ?)',
                  ('admin@example.com', hash_password('admin123'), 'Админ', 'Админов'))
        print("Создан тестовый админ: admin@example.com / admin123")

    c.execute('SELECT 1 FROM users WHERE email = ?', ('user@example.com',))
    if not c.fetchone():
        c.execute('INSERT INTO users (email, password, first_name, last_name) VALUES (?, ?, ?, ?)',
                  ('user@example.com', hash_password('user123'), 'Иван', 'Иванов'))
        print("Создан тестовый пользователь: user@example.com / user123")

    conn.commit()
    conn.close()

    print("\nСервер запущен на http://localhost:5000")
    print("\nДоступные эндпоинты:")
    print("  POST /api/register    - регистрация")
    print("  POST /api/login       - вход")
    print("  POST /api/logout      - выход")
    print("  GET  /api/profile     - профиль")
    print("  PUT  /api/profile     - обновление профиля")
    print("  POST /api/profile/delete - удаление аккаунта")
    print("  GET  /api/products    - демо товары")
    print("  GET  /api/orders      - демо заказы")
    print("  GET  /api/admin/users - демо админка (только для admin@example.com)")
    print("\nПример запроса регистрации:")
    print('''
curl -X POST http://localhost:5000/api/register \\
  -H "Content-Type: application/json" \\
  -d '{"email": "test@test.com", "password": "test123", "password_confirm": "test123", "first_name": "Тест", "last_name": "Тестов"}'
    ''')

    print("\n" + "=" * 50)
    app.run(debug=True, port=5000)