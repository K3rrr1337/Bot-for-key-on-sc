from fastapi import FastAPI, HTTPException, Depends
import asyncpg
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
import os
from pydantic import BaseModel
from typing import Optional

app = FastAPI()

DATABASE_URL = os.getenv("DATABASE_URL")

async def get_db():
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        yield conn
    finally:
        await conn.close()

# ========== MODELS ==========
class AuthRequest(BaseModel):
    login: str
    password: str
    key: str
    hwid: Optional[str] = None  # Добавляем HWID

class KeyActivateRequest(BaseModel):
    key_code: str
    user_id: int
    hwid: Optional[str] = None  # Добавляем HWID

class UserCreateRequest(BaseModel):
    login: str
    password: str
    telegram_id: Optional[int] = None

class KeyCreateRequest(BaseModel):
    days: int
    user_id: Optional[int] = None

class BanRequest(BaseModel):
    login: str

class HWIDBindRequest(BaseModel):
    user_id: int
    hwid: str

class HWIDCheckRequest(BaseModel):
    hwid: str

# ========== HELPER FUNCTIONS ==========
def hash_hwid(hwid: str) -> str:
    """Хеширует HWID для безопасного хранения"""
    return hashlib.sha256(hwid.encode()).hexdigest()

def generate_promo_code(length: int = 8) -> str:
    """Генерирует промокод из 8 символов"""
    import string
    characters = string.ascii_uppercase + string.digits
    characters = characters.replace('O', '').replace('0', '').replace('I', '').replace('1', '')
    
    while True:
        code = ''.join(secrets.choice(characters) for _ in range(length))
        if len(set(code)) >= length // 2:
            return code

# ========== API ENDPOINTS ==========
@app.get("/")
async def root():
    return {
        "status": "Astra Key API is running",
        "version": "3.0",
        "features": ["HWID Support", "Key Management", "User Management"],
        "endpoints": [
            "/api/auth",
            "/api/activate_key",
            "/api/users",
            "/api/keys",
            "/api/changelog",
            "/api/hwid"
        ]
    }

# ========== AUTH ENDPOINT ==========
@app.post("/api/auth")
async def auth(request: AuthRequest, db=Depends(get_db)):
    """Аутентификация пользователя с проверкой ключа и HWID"""
    user = await db.fetchrow(
        "SELECT id, password_hash, salt, is_banned FROM users WHERE login = $1",
        request.login
    )
    if not user:
        raise HTTPException(401, "Invalid login")
    
    if user['is_banned']:
        raise HTTPException(403, "User is banned")
    
    # Проверка пароля
    salt = user['salt']
    input_hash = hashlib.pbkdf2_hmac('sha256', request.password.encode(), salt.encode(), 100000).hex()
    if not hmac.compare_digest(input_hash, user['password_hash']):
        raise HTTPException(401, "Invalid password")
    
    # Проверка ключа
    key = await db.fetchrow(
        """
        SELECT id, days_valid, used_by, used_at, hwid_hash, is_active 
        FROM keys 
        WHERE key_code = $1
        """,
        request.key
    )
    if not key:
        raise HTTPException(401, "Invalid key")
    
    if not key['is_active']:
        raise HTTPException(401, "Key is not active")
    
    # Проверка, что ключ принадлежит этому пользователю
    if key['used_by'] and key['used_by'] != user['id']:
        raise HTTPException(401, "Key already used by another user")
    
    # Проверка HWID если он передан
    if request.hwid:
        hwid_hash = hash_hwid(request.hwid)
        
        # Проверяем, привязан ли HWID к этому пользователю
        hwid_record = await db.fetchrow(
            "SELECT user_id, hwid_hash FROM hwid_history WHERE hwid_hash = $1",
            hwid_hash
        )
        
        if hwid_record:
            if hwid_record['user_id'] != user['id']:
                raise HTTPException(403, "HWID already bound to another user")
        else:
            # Если HWID не привязан, проверяем есть ли у пользователя привязанный HWID
            user_hwid = await db.fetchrow(
                "SELECT hwid_hash FROM hwid_history WHERE user_id = $1",
                user['id']
            )
            
            if user_hwid:
                raise HTTPException(403, "User already has a bound HWID")
            
            # Если ключ уже был использован, но без HWID
            if key['used_by'] and key['used_by'] == user['id'] and not key['hwid_hash']:
                # Привязываем HWID к существующему ключу
                await db.execute(
                    """
                    INSERT INTO hwid_history (user_id, hwid_hash, key_id) 
                    VALUES ($1, $2, $3)
                    """,
                    user['id'], hwid_hash, key['id']
                )
                
                await db.execute(
                    "UPDATE keys SET hwid_hash = $1, activated_at = NOW() WHERE id = $2",
                    hwid_hash, key['id']
                )
            
            # Если ключ не использован, используем его и привязываем HWID
            elif not key['used_by']:
                await db.execute(
                    "UPDATE keys SET used_by = $1, used_at = $2 WHERE id = $3",
                    user['id'], datetime.now(), key['id']
                )
                
                await db.execute(
                    """
                    INSERT INTO hwid_history (user_id, hwid_hash, key_id) 
                    VALUES ($1, $2, $3)
                    """,
                    user['id'], hwid_hash, key['id']
                )
                
                await db.execute(
                    "UPDATE keys SET hwid_hash = $1, activated_at = NOW() WHERE id = $2",
                    hwid_hash, key['id']
                )
        used_at = datetime.now()
    else:
        # Если HWID не передан, проверяем что ключ уже активирован
        if not key['used_by']:
            raise HTTPException(400, "HWID required for key activation")
        
        # Проверяем, привязан ли ключ к HWID
        if key['hwid_hash']:
            raise HTTPException(400, "This key requires HWID authentication")
        
        used_at = key['used_at'] if key['used_at'] else datetime.now()
    
    # Расчет оставшихся дней
    expiry = used_at + timedelta(days=key['days_valid'])
    days_left = (expiry - datetime.now()).days
    
    return {
        "success": True,
        "days_left": max(0, days_left),
        "username": request.login,
        "user_id": user['id'],
        "key_expiry": expiry.isoformat(),
        "is_active": days_left > 0,
        "has_hwid": bool(key['hwid_hash'] or request.hwid)
    }

# ========== KEY ACTIVATION ==========
@app.post("/api/activate_key")
async def activate_key(request: KeyActivateRequest, db=Depends(get_db)):
    """Активация ключа для пользователя"""
    user = await db.fetchrow(
        "SELECT id, is_banned FROM users WHERE id = $1",
        request.user_id
    )
    if not user:
        raise HTTPException(404, "User not found")
    
    if user['is_banned']:
        raise HTTPException(403, "User is banned")
    
    # Проверяем, нет ли у пользователя активного ключа
    has_active = await db.fetchval(
        "SELECT COUNT(*) FROM keys WHERE used_by = $1 AND is_active = TRUE",
        request.user_id
    )
    if has_active > 0:
        raise HTTPException(400, "User already has an active key")
    
    key = await db.fetchrow(
        """
        SELECT id, days_valid, used_by, used_at, is_active 
        FROM keys 
        WHERE key_code = $1
        """,
        request.key_code
    )
    if not key:
        raise HTTPException(404, "Key not found")
    
    if key['used_by'] and key['used_by'] != user['id']:
        raise HTTPException(400, "Key already used")
    
    if not key['is_active']:
        raise HTTPException(400, "Key is not active")
    
    # Если передан HWID, привязываем его
    if request.hwid:
        hwid_hash = hash_hwid(request.hwid)
        
        # Проверяем, не привязан ли HWID к другому пользователю
        existing_hwid = await db.fetchrow(
            "SELECT user_id FROM hwid_history WHERE hwid_hash = $1",
            hwid_hash
        )
        
        if existing_hwid and existing_hwid['user_id'] != user['id']:
            raise HTTPException(400, "HWID already bound to another user")
        
        # Проверяем, нет ли у пользователя другого HWID
        user_hwid = await db.fetchrow(
            "SELECT hwid_hash FROM hwid_history WHERE user_id = $1",
            user['id']
        )
        
        if user_hwid:
            raise HTTPException(400, "User already has a bound HWID")
    
    # Активируем ключ
    await db.execute(
        "UPDATE keys SET used_by = $1, used_at = $2, is_active = TRUE WHERE id = $3",
        user['id'], datetime.now(), key['id']
    )
    
    # Если есть HWID, сохраняем его
    if request.hwid:
        hwid_hash = hash_hwid(request.hwid)
        await db.execute(
            """
            INSERT INTO hwid_history (user_id, hwid_hash, key_id) 
            VALUES ($1, $2, $3)
            """,
            user['id'], hwid_hash, key['id']
        )
        
        await db.execute(
            "UPDATE keys SET hwid_hash = $1, activated_at = NOW() WHERE id = $2",
            hwid_hash, key['id']
        )
    
    expiry = datetime.now() + timedelta(days=key['days_valid'])
    
    return {
        "success": True,
        "message": "Key activated successfully",
        "expiry": expiry.isoformat(),
        "days_valid": key['days_valid'],
        "has_hwid": bool(request.hwid)
    }

# ========== HWID ENDPOINTS ==========
@app.post("/api/hwid/bind")
async def bind_hwid(request: HWIDBindRequest, db=Depends(get_db)):
    """Привязка HWID к пользователю"""
    user = await db.fetchrow(
        "SELECT id, is_banned FROM users WHERE id = $1",
        request.user_id
    )
    if not user:
        raise HTTPException(404, "User not found")
    
    if user['is_banned']:
        raise HTTPException(403, "User is banned")
    
    # Проверяем, есть ли у пользователя активный ключ
    active_key = await db.fetchrow(
        "SELECT id FROM keys WHERE used_by = $1 AND is_active = TRUE",
        request.user_id
    )
    if not active_key:
        raise HTTPException(400, "User has no active key")
    
    hwid_hash = hash_hwid(request.hwid)
    
    # Проверяем, не привязан ли HWID к другому пользователю
    existing = await db.fetchrow(
        "SELECT user_id FROM hwid_history WHERE hwid_hash = $1",
        hwid_hash
    )
    if existing and existing['user_id'] != user['id']:
        raise HTTPException(400, "HWID already bound to another user")
    
    # Проверяем, нет ли у пользователя другого HWID
    user_hwid = await db.fetchrow(
        "SELECT hwid_hash FROM hwid_history WHERE user_id = $1",
        user['id']
    )
    if user_hwid:
        raise HTTPException(400, "User already has a bound HWID")
    
    # Привязываем HWID
    await db.execute(
        """
        INSERT INTO hwid_history (user_id, hwid_hash, key_id) 
        VALUES ($1, $2, $3)
        """,
        user['id'], hwid_hash, active_key['id']
    )
    
    await db.execute(
        "UPDATE keys SET hwid_hash = $1, activated_at = NOW() WHERE id = $2",
        hwid_hash, active_key['id']
    )
    
    return {
        "success": True,
        "message": "HWID bound successfully",
        "user_id": user['id']
    }

@app.post("/api/hwid/check")
async def check_hwid(request: HWIDCheckRequest, db=Depends(get_db)):
    """Проверка HWID"""
    hwid_hash = hash_hwid(request.hwid)
    
    record = await db.fetchrow(
        """
        SELECT h.user_id, h.created_at, u.login, u.is_banned,
               k.key_code, k.days_valid
        FROM hwid_history h
        JOIN users u ON h.user_id = u.id
        LEFT JOIN keys k ON h.key_id = k.id
        WHERE h.hwid_hash = $1
        """,
        hwid_hash
    )
    
    if not record:
        return {
            "found": False,
            "message": "HWID not found in system"
        }
    
    return {
        "found": True,
        "user_id": record['user_id'],
        "username": record['login'],
        "is_banned": record['is_banned'],
        "bound_at": record['created_at'].isoformat() if record['created_at'] else None,
        "key": record['key_code'] if record['key_code'] else None,
        "days_valid": record['days_valid']
    }

@app.get("/api/hwid/user/{user_id}")
async def get_user_hwid(user_id: int, db=Depends(get_db)):
    """Получить HWID пользователя"""
    hwid = await db.fetchrow(
        """
        SELECT h.hwid_hash, h.created_at, k.key_code 
        FROM hwid_history h
        LEFT JOIN keys k ON h.key_id = k.id
        WHERE h.user_id = $1
        ORDER BY h.created_at DESC
        LIMIT 1
        """,
        user_id
    )
    
    if not hwid:
        return {
            "has_hwid": False,
            "message": "User has no HWID bound"
        }
    
    # Показываем только первые 10 символов для безопасности
    full_hash = hwid['hwid_hash']
    partial_hwid = full_hash[:10] + "..." if full_hash else None
    
    return {
        "has_hwid": True,
        "hwid_hash": partial_hwid,
        "bound_at": hwid['created_at'].isoformat() if hwid['created_at'] else None,
        "key_code": hwid['key_code']
    }

# ========== USERS ENDPOINTS ==========
@app.get("/api/users")
async def get_users(db=Depends(get_db)):
    """Получить список всех пользователей"""
    users = await db.fetch(
        """
        SELECT u.id, u.login, u.is_banned, u.created_at, u.telegram_id,
               EXISTS(SELECT 1 FROM hwid_history h WHERE h.user_id = u.id) as has_hwid,
               COUNT(k.id) as active_keys
        FROM users u
        LEFT JOIN keys k ON u.id = k.used_by AND k.is_active = TRUE
        GROUP BY u.id
        ORDER BY u.created_at DESC
        """
    )
    
    return {
        "users": [
            {
                "id": user['id'],
                "login": user['login'],
                "is_banned": user['is_banned'],
                "telegram_id": user['telegram_id'],
                "created_at": user['created_at'].isoformat() if user['created_at'] else None,
                "has_hwid": user['has_hwid'],
                "active_keys": user['active_keys']
            }
            for user in users
        ]
    }

@app.get("/api/users/{user_id}/keys")
async def get_user_keys(user_id: int, db=Depends(get_db)):
    """Получить ключи пользователя"""
    keys = await db.fetch(
        """
        SELECT id, key_code, days_valid, used_at, created_at, 
               hwid_hash, is_active, activated_at
        FROM keys 
        WHERE used_by = $1 
        ORDER BY used_at DESC
        """,
        user_id
    )
    
    return {
        "keys": [
            {
                "id": key['id'],
                "key_code": key['key_code'],
                "days_valid": key['days_valid'],
                "used_at": key['used_at'].isoformat() if key['used_at'] else None,
                "created_at": key['created_at'].isoformat() if key['created_at'] else None,
                "has_hwid": bool(key['hwid_hash']),
                "is_active": key['is_active'],
                "activated_at": key['activated_at'].isoformat() if key['activated_at'] else None
            }
            for key in keys
        ]
    }

# ========== KEYS ENDPOINTS ==========
@app.get("/api/keys/check/{key_code}")
async def check_key(key_code: str, db=Depends(get_db)):
    """Проверить статус ключа"""
    key = await db.fetchrow(
        """
        SELECT key_code, days_valid, used_by, used_at, created_by, 
               hwid_hash, is_active, activated_at
        FROM keys 
        WHERE key_code = $1
        """,
        key_code
    )
    
    if not key:
        raise HTTPException(404, "Key not found")
    
    is_used = key['used_by'] is not None
    used_at = key['used_at']
    
    # Получаем информацию о пользователе если ключ использован
    user_info = None
    if key['used_by']:
        user = await db.fetchrow(
            "SELECT login FROM users WHERE id = $1",
            key['used_by']
        )
        if user:
            user_info = user['login']
    
    return {
        "key_code": key['key_code'],
        "is_used": is_used,
        "used_by_id": key['used_by'],
        "used_by": user_info,
        "used_at": used_at.isoformat() if used_at else None,
        "days_valid": key['days_valid'],
        "is_active": key['is_active'],
        "has_hwid": bool(key['hwid_hash']),
        "activated_at": key['activated_at'].isoformat() if key['activated_at'] else None
    }

@app.get("/api/keys/pending")
async def get_pending_keys(db=Depends(get_db)):
    """Получить список неиспользованных ключей"""
    keys = await db.fetch(
        """
        SELECT id, key_code, days_valid, created_at, created_by
        FROM keys 
        WHERE used_by IS NULL AND is_active = TRUE
        ORDER BY created_at DESC
        """
    )
    
    return {
        "pending_keys": [
            {
                "id": key['id'],
                "key_code": key['key_code'],
                "days_valid": key['days_valid'],
                "created_at": key['created_at'].isoformat() if key['created_at'] else None
            }
            for key in keys
        ]
    }

@app.get("/api/keys/used")
async def get_used_keys(db=Depends(get_db)):
    """Получить список использованных ключей"""
    keys = await db.fetch(
        """
        SELECT k.id, k.key_code, k.days_valid, k.used_at, 
               u.login as used_by_login, k.hwid_hash, k.is_active
        FROM keys k
        LEFT JOIN users u ON k.used_by = u.id
        WHERE k.used_by IS NOT NULL
        ORDER BY k.used_at DESC
        """
    )
    
    return {
        "used_keys": [
            {
                "id": key['id'],
                "key_code": key['key_code'],
                "days_valid": key['days_valid'],
                "used_at": key['used_at'].isoformat() if key['used_at'] else None,
                "used_by": key['used_by_login'],
                "has_hwid": bool(key['hwid_hash']),
                "is_active": key['is_active']
            }
            for key in keys
        ]
    }

@app.get("/api/keys/expiring")
async def get_expiring_keys(days: int = 7, db=Depends(get_db)):
    """Получить ключи, срок действия которых истекает через указанное количество дней"""
    expiry_threshold = datetime.now() + timedelta(days=days)
    
    keys = await db.fetch(
        """
        SELECT k.id, k.key_code, k.days_valid, k.used_at, 
               u.login as used_by_login,
               (k.used_at + (k.days_valid || ' days')::INTERVAL) as expiry_date,
               k.hwid_hash
        FROM keys k
        LEFT JOIN users u ON k.used_by = u.id
        WHERE k.used_by IS NOT NULL
          AND k.is_active = TRUE
          AND (k.used_at + (k.days_valid || ' days')::INTERVAL) <= $1
          AND (k.used_at + (k.days_valid || ' days')::INTERVAL) > NOW()
        ORDER BY expiry_date ASC
        """,
        expiry_threshold
    )
    
    return {
        "expiring_keys": [
            {
                "id": key['id'],
                "key_code": key['key_code'],
                "used_by": key['used_by_login'],
                "expiry_date": key['expiry_date'].isoformat() if key['expiry_date'] else None,
                "days_left": (key['expiry_date'] - datetime.now()).days if key['expiry_date'] else 0,
                "has_hwid": bool(key['hwid_hash'])
            }
            for key in keys
        ]
    }

# ========== CHANGELOG ==========
@app.get("/api/changelog")
async def get_changelog(limit: int = 10, db=Depends(get_db)):
    """Получить последние записи ченжлога"""
    logs = await db.fetch(
        """
        SELECT c.id, c.content, c.created_at, u.login as created_by
        FROM changelog c
        LEFT JOIN users u ON c.created_by = u.id
        ORDER BY c.created_at DESC 
        LIMIT $1
        """,
        limit
    )
    
    return {
        "changelog": [
            {
                "id": log['id'],
                "content": log['content'],
                "created_at": log['created_at'].isoformat() if log['created_at'] else None,
                "created_by": log['created_by']
            }
            for log in logs
        ]
    }

# ========== ADMIN ENDPOINTS ==========
@app.post("/api/admin/create_key")
async def create_key(request: KeyCreateRequest, db=Depends(get_db)):
    """Создать новый ключ (только для админов)"""
    key_code = generate_promo_code(8)
    
    # Проверяем уникальность ключа
    existing = await db.fetchrow(
        "SELECT id FROM keys WHERE key_code = $1",
        key_code
    )
    while existing:
        key_code = generate_promo_code(8)
        existing = await db.fetchrow(
            "SELECT id FROM keys WHERE key_code = $1",
            key_code
        )
    
    try:
        await db.execute(
            """
            INSERT INTO keys (key_code, days_valid, created_by, is_active) 
            VALUES ($1, $2, $3, TRUE)
            """,
            key_code, request.days, request.user_id
        )
        
        return {
            "success": True,
            "key_code": key_code,
            "days_valid": request.days,
            "message": "Key created successfully"
        }
    except Exception as e:
        raise HTTPException(400, f"Failed to create key: {str(e)}")

@app.post("/api/admin/create_user")
async def create_user(request: UserCreateRequest, db=Depends(get_db)):
    """Создать нового пользователя (только для админов)"""
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        'sha256', 
        request.password.encode(), 
        salt.encode(), 
        100000
    ).hex()
    
    try:
        result = await db.fetchrow(
            """
            INSERT INTO users (login, password_hash, salt, telegram_id) 
            VALUES ($1, $2, $3, $4) 
            RETURNING id
            """,
            request.login, password_hash, salt, request.telegram_id
        )
        
        return {
            "success": True,
            "login": request.login,
            "user_id": result['id'],
            "telegram_id": request.telegram_id
        }
    except Exception as e:
        raise HTTPException(400, f"Failed to create user: {str(e)}")

@app.post("/api/admin/ban_user")
async def ban_user(request: BanRequest, db=Depends(get_db)):
    """Забанить пользователя (только для админов)"""
    user = await db.fetchrow(
        "SELECT id FROM users WHERE login = $1",
        request.login
    )
    
    if not user:
        raise HTTPException(404, "User not found")
    
    # Баним пользователя
    result = await db.execute(
        "UPDATE users SET is_banned = TRUE WHERE login = $1",
        request.login
    )
    
    # Деактивируем все ключи пользователя
    await db.execute(
        "UPDATE keys SET is_active = FALSE WHERE used_by = $1",
        user['id']
    )
    
    return {
        "success": True,
        "message": f"User {request.login} has been banned",
        "keys_deactivated": True
    }

@app.post("/api/admin/unban_user")
async def unban_user(request: BanRequest, db=Depends(get_db)):
    """Разбанить пользователя (только для админов)"""
    result = await db.execute(
        "UPDATE users SET is_banned = FALSE WHERE login = $1",
        request.login
    )
    
    if result == "UPDATE 0":
        raise HTTPException(404, "User not found")
    
    return {
        "success": True,
        "message": f"User {request.login} has been unbanned"
    }

@app.post("/api/admin/deactivate_key")
async def deactivate_key(key_code: str, db=Depends(get_db)):
    """Деактивировать ключ (только для админов)"""
    result = await db.execute(
        "UPDATE keys SET is_active = FALSE WHERE key_code = $1",
        key_code
    )
    
    if result == "UPDATE 0":
        raise HTTPException(404, "Key not found")
    
    return {
        "success": True,
        "message": f"Key {key_code} has been deactivated"
    }

# ========== DATABASE INITIALIZATION ==========
@app.on_event("startup")
async def startup():
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        # Создаем все таблицы с полной структурой
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                login VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                salt VARCHAR(50) NOT NULL,
                is_banned BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                telegram_id BIGINT UNIQUE
            )
        """)
        
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                id SERIAL PRIMARY KEY,
                key_code VARCHAR(50) UNIQUE NOT NULL,
                days_valid INTEGER NOT NULL,
                used_by INTEGER REFERENCES users(id),
                used_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER REFERENCES users(id),
                hwid_hash VARCHAR(255),
                is_active BOOLEAN DEFAULT TRUE,
                activated_at TIMESTAMP
            )
        """)
        
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS hwid_history (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                hwid_hash VARCHAR(255) NOT NULL,
                key_id INTEGER REFERENCES keys(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, hwid_hash)
            )
        """)
        
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS key_requests (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                status VARCHAR(20) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processed_at TIMESTAMP,
                processed_by INTEGER REFERENCES users(id)
            )
        """)
        
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS changelog (
                id SERIAL PRIMARY KEY,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER REFERENCES users(id)
            )
        """)
        
        print("✅ Database tables created successfully with HWID support")
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
    finally:
        await conn.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
