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

class KeyActivateRequest(BaseModel):
    key_code: str
    user_id: int

class UserCreateRequest(BaseModel):
    login: str
    password: str
    telegram_id: Optional[int] = None

class KeyCreateRequest(BaseModel):
    days: int
    user_id: Optional[int] = None

class BanRequest(BaseModel):
    login: str

# ========== API ENDPOINTS ==========
@app.get("/")
async def root():
    return {
        "status": "Astra Key API is running",
        "version": "2.0",
        "endpoints": [
            "/api/auth",
            "/api/activate_key",
            "/api/users",
            "/api/keys",
            "/api/changelog"
        ]
    }

@app.post("/api/auth")
async def auth(request: AuthRequest, db=Depends(get_db)):
    """Аутентификация пользователя с проверкой ключа"""
    user = await db.fetchrow(
        "SELECT id, password_hash, salt, is_banned FROM users WHERE login = $1",
        request.login
    )
    if not user:
        raise HTTPException(401, "Invalid login")
    
    if user['is_banned']:
        raise HTTPException(403, "Banned")
    
    salt = user['salt']
    input_hash = hashlib.pbkdf2_hmac('sha256', request.password.encode(), salt.encode(), 100000).hex()
    if not hmac.compare_digest(input_hash, user['password_hash']):
        raise HTTPException(401, "Invalid password")
    
    key = await db.fetchrow(
        "SELECT id, days_valid, used_by, used_at FROM keys WHERE key_code = $1",
        request.key
    )
    if not key:
        raise HTTPException(401, "Invalid key")
    
    if key['used_by'] and key['used_by'] != user['id']:
        raise HTTPException(401, "Key already used")
    
    if not key['used_by']:
        await db.execute(
            "UPDATE keys SET used_by = $1, used_at = $2 WHERE id = $3",
            user['id'], datetime.now(), key['id']
        )
        used_at = datetime.now()
    else:
        used_at = key['used_at']
    
    expiry = used_at + timedelta(days=key['days_valid'])
    days_left = (expiry - datetime.now()).days
    
    return {
        "success": True,
        "days_left": max(0, days_left),
        "username": request.login,
        "user_id": user['id'],
        "key_expiry": expiry.isoformat(),
        "is_active": days_left > 0
    }

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
    
    key = await db.fetchrow(
        "SELECT id, days_valid, used_by, used_at FROM keys WHERE key_code = $1",
        request.key_code
    )
    if not key:
        raise HTTPException(404, "Key not found")
    
    if key['used_by'] and key['used_by'] != user['id']:
        raise HTTPException(400, "Key already used")
    
    await db.execute(
        "UPDATE keys SET used_by = $1, used_at = $2 WHERE id = $3",
        user['id'], datetime.now(), key['id']
    )
    
    expiry = datetime.now() + timedelta(days=key['days_valid'])
    
    return {
        "success": True,
        "message": "Key activated successfully",
        "expiry": expiry.isoformat(),
        "days_valid": key['days_valid']
    }

@app.get("/api/users")
async def get_users(db=Depends(get_db)):
    """Получить список всех пользователей"""
    users = await db.fetch(
        "SELECT id, login, is_banned, created_at, telegram_id FROM users ORDER BY created_at DESC"
    )
    
    return {
        "users": [
            {
                "id": user['id'],
                "login": user['login'],
                "is_banned": user['is_banned'],
                "telegram_id": user['telegram_id'],
                "created_at": user['created_at'].isoformat() if user['created_at'] else None
            }
            for user in users
        ]
    }

@app.get("/api/users/{user_id}/keys")
async def get_user_keys(user_id: int, db=Depends(get_db)):
    """Получить ключи пользователя"""
    keys = await db.fetch(
        "SELECT id, key_code, days_valid, used_at, created_at FROM keys WHERE used_by = $1 ORDER BY used_at DESC",
        user_id
    )
    
    return {
        "keys": [
            {
                "id": key['id'],
                "key_code": key['key_code'],
                "days_valid": key['days_valid'],
                "used_at": key['used_at'].isoformat() if key['used_at'] else None,
                "created_at": key['created_at'].isoformat() if key['created_at'] else None
            }
            for key in keys
        ]
    }

@app.get("/api/keys/check/{key_code}")
async def check_key(key_code: str, db=Depends(get_db)):
    """Проверить статус ключа"""
    key = await db.fetchrow(
        "SELECT key_code, days_valid, used_by, used_at FROM keys WHERE key_code = $1",
        key_code
    )
    
    if not key:
        raise HTTPException(404, "Key not found")
    
    is_used = key['used_by'] is not None
    used_at = key['used_at']
    
    return {
        "key_code": key['key_code'],
        "is_used": is_used,
        "used_by": key['used_by'],
        "used_at": used_at.isoformat() if used_at else None,
        "days_valid": key['days_valid'],
        "is_active": not is_used
    }

@app.get("/api/changelog")
async def get_changelog(limit: int = 10, db=Depends(get_db)):
    """Получить последние записи ченжлога"""
    logs = await db.fetch(
        "SELECT id, content, created_at FROM changelog ORDER BY created_at DESC LIMIT $1",
        limit
    )
    
    return {
        "changelog": [
            {
                "id": log['id'],
                "content": log['content'],
                "created_at": log['created_at'].isoformat() if log['created_at'] else None
            }
            for log in logs
        ]
    }

@app.get("/api/keys/pending")
async def get_pending_keys(db=Depends(get_db)):
    """Получить список ожидающих активации ключей"""
    keys = await db.fetch(
        "SELECT id, key_code, days_valid, created_at FROM keys WHERE used_by IS NULL"
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
        SELECT k.id, k.key_code, k.days_valid, k.used_at, u.login as used_by_login
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
                "used_by": key['used_by_login']
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
        SELECT k.id, k.key_code, k.days_valid, k.used_at, u.login as used_by_login,
               (k.used_at + (k.days_valid || ' days')::INTERVAL) as expiry_date
        FROM keys k
        LEFT JOIN users u ON k.used_by = u.id
        WHERE k.used_by IS NOT NULL
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
                "days_left": (key['expiry_date'] - datetime.now()).days if key['expiry_date'] else 0
            }
            for key in keys
        ]
    }

# ========== ADMIN ENDPOINTS ==========
@app.post("/api/admin/create_key")
async def create_key(request: KeyCreateRequest, db=Depends(get_db)):
    """Создать новый ключ (только для админов)"""
    key_code = secrets.token_hex(16)
    
    try:
        # Проверяем существование таблицы и колонки
        column_exists = await db.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'keys' AND column_name = 'created_by'
            )
        """)
        
        if column_exists:
            await db.execute(
                "INSERT INTO keys (key_code, days_valid, created_by) VALUES ($1, $2, $3)",
                key_code, request.days, request.user_id
            )
        else:
            await db.execute(
                "INSERT INTO keys (key_code, days_valid) VALUES ($1, $2)",
                key_code, request.days
            )
        
        return {
            "success": True,
            "key_code": key_code,
            "days_valid": request.days
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
        # Проверяем существование колонки telegram_id
        column_exists = await db.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'users' AND column_name = 'telegram_id'
            )
        """)
        
        if column_exists and request.telegram_id is not None:
            result = await db.fetchrow(
                """
                INSERT INTO users (login, password_hash, salt, telegram_id) 
                VALUES ($1, $2, $3, $4) 
                RETURNING id
                """,
                request.login, password_hash, salt, request.telegram_id
            )
        else:
            result = await db.fetchrow(
                """
                INSERT INTO users (login, password_hash, salt) 
                VALUES ($1, $2, $3) 
                RETURNING id
                """,
                request.login, password_hash, salt
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
    result = await db.execute(
        "UPDATE users SET is_banned = TRUE WHERE login = $1",
        request.login
    )
    
    if result == "UPDATE 0":
        raise HTTPException(404, "User not found")
    
    return {
        "success": True,
        "message": f"User {request.login} has been banned"
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

@app.get("/api/admin/requests")
async def get_requests(db=Depends(get_db)):
    """Получить все заявки на ключи (только для админов)"""
    requests = await db.fetch(
        """
        SELECT kr.id, kr.user_id, u.login, u.is_banned, kr.status, kr.created_at, kr.processed_at
        FROM key_requests kr
        JOIN users u ON kr.user_id = u.id
        ORDER BY kr.created_at DESC
        """
    )
    
    return {
        "requests": [
            {
                "id": req['id'],
                "user_id": req['user_id'],
                "login": req['login'],
                "is_banned": req['is_banned'],
                "status": req['status'],
                "created_at": req['created_at'].isoformat() if req['created_at'] else None,
                "processed_at": req['processed_at'].isoformat() if req['processed_at'] else None
            }
            for req in requests
        ]
    }

@app.get("/api/admin/stats")
async def get_stats(db=Depends(get_db)):
    """Получить статистику (только для админов)"""
    total_users = await db.fetchval("SELECT COUNT(*) FROM users")
    banned_users = await db.fetchval("SELECT COUNT(*) FROM users WHERE is_banned = TRUE")
    total_keys = await db.fetchval("SELECT COUNT(*) FROM keys")
    used_keys = await db.fetchval("SELECT COUNT(*) FROM keys WHERE used_by IS NOT NULL")
    pending_requests = await db.fetchval("SELECT COUNT(*) FROM key_requests WHERE status = 'pending'")
    
    return {
        "total_users": total_users,
        "banned_users": banned_users,
        "active_users": total_users - banned_users,
        "total_keys": total_keys,
        "used_keys": used_keys,
        "pending_keys": total_keys - used_keys,
        "pending_requests": pending_requests
    }

# ========== DATABASE INITIALIZATION ==========
@app.on_event("startup")
async def startup():
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        # Создаем таблицы с правильной структурой
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
        
        # Проверяем наличие колонки created_by в keys
        column_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'keys' AND column_name = 'created_by'
            )
        """)
        
        if not column_exists:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS keys (
                    id SERIAL PRIMARY KEY,
                    key_code VARCHAR(50) UNIQUE NOT NULL,
                    days_valid INTEGER NOT NULL,
                    used_by INTEGER REFERENCES users(id),
                    used_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
        else:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS keys (
                    id SERIAL PRIMARY KEY,
                    key_code VARCHAR(50) UNIQUE NOT NULL,
                    days_valid INTEGER NOT NULL,
                    used_by INTEGER REFERENCES users(id),
                    used_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_by INTEGER REFERENCES users(id)
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
        
        print("✅ Database tables created successfully")
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
    finally:
        await conn.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
