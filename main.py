# main.py
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import asyncpg
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
import os
from pydantic import BaseModel

app = FastAPI()
security = HTTPBearer()

# ========== ПРОВЕРКА ПЕРЕМЕННОЙ ==========
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print("❌ DATABASE_URL not set!")
    raise ValueError("DATABASE_URL environment variable is required")

print(f"✅ Database URL: {DATABASE_URL[:30]}...")

# ========== ПОДКЛЮЧЕНИЕ К БД ==========
async def get_db():
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        yield conn
    finally:
        await conn.close()

# ========== МОДЕЛИ ==========
class AuthRequest(BaseModel):
    login: str
    password: str
    key: str

class KeyGenRequest(BaseModel):
    days: int

# ========== API ЭНДПОИНТЫ ==========

@app.get("/")
async def root():
    return {"status": "API is running", "message": "Astra Auth System"}

@app.post("/api/auth")
async def auth(request: AuthRequest, db=Depends(get_db)):
    try:
        # Проверяем пользователя
        user = await db.fetchrow(
            "SELECT id, password_hash, salt, is_banned FROM users WHERE login = $1", 
            request.login
        )
        if not user:
            raise HTTPException(status_code=401, detail="Invalid login or password")
        
        if user['is_banned']:
            raise HTTPException(status_code=403, detail="User is banned")
        
        # Проверка пароля
        salt = user['salt']
        input_hash = hashlib.pbkdf2_hmac('sha256', request.password.encode(), salt.encode(), 100000).hex()
        if not hmac.compare_digest(input_hash, user['password_hash']):
            raise HTTPException(status_code=401, detail="Invalid login or password")
        
        # Проверка ключа
        key = await db.fetchrow(
            "SELECT id, days_valid, used_by FROM keys WHERE key_code = $1", 
            request.key
        )
        if not key:
            raise HTTPException(status_code=401, detail="Invalid key")
        
        if key['used_by'] and key['used_by'] != user['id']:
            raise HTTPException(status_code=401, detail="Key already used by another user")
        
        # Привязываем ключ
        if not key['used_by']:
            await db.execute(
                "UPDATE keys SET used_by = $1, used_at = $2 WHERE id = $3",
                user['id'], datetime.now(), key['id']
            )
        
        # Считаем оставшиеся дни
        used_at = await db.fetchval("SELECT used_at FROM keys WHERE id = $1", key['id'])
        expiry = used_at + timedelta(days=key['days_valid'])
        days_left = (expiry - datetime.now()).days
        
        return {
            "success": True,
            "days_left": max(0, days_left),
            "username": request.login,
            "user_id": user['id']
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Auth error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/key/generate")
async def generate_key(request: KeyGenRequest, credentials: HTTPAuthorizationCredentials = Depends(security), db=Depends(get_db)):
    """
    Генерация ключа (только для админов)
    """
    token = credentials.credentials
    
    # Проверка админского токена (простая заглушка)
    # В реальном проекте используй нормальную проверку
    ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "1908250518")
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    key_code = secrets.token_hex(16)
    
    try:
        await db.execute(
            "INSERT INTO keys (key_code, days_valid) VALUES ($1, $2)",
            key_code, request.days
        )
        return {"key": key_code, "days": request.days, "success": True}
    except Exception as e:
        print(f"❌ Generate key error: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate key")

# ========== ИНИЦИАЛИЗАЦИЯ БД ПРИ ЗАПУСКЕ ==========
@app.on_event("startup")
async def startup():
    print("🚀 Starting API...")
    try:
        conn = await asyncpg.connect(DATABASE_URL)
        
        # Создаем таблицу пользователей
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                login VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                salt VARCHAR(50) NOT NULL,
                is_banned BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("✅ Users table ready")
        
        # Создаем таблицу ключей
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
        print("✅ Keys table ready")
        
        await conn.close()
        print("✅ Database initialized successfully!")
        
        # Добавляем тестового пользователя если нет никого
        test_user = await conn.fetchrow("SELECT * FROM users LIMIT 1")
        if not test_user:
            print("📝 No users found, creating test user...")
            salt = secrets.token_hex(16)
            password_hash = hashlib.pbkdf2_hmac('sha256', "123".encode(), salt.encode(), 100000).hex()
            await conn.execute(
                "INSERT INTO users (login, password_hash, salt) VALUES ($1, $2, $3)",
                "admin", password_hash, salt
            )
            print("✅ Test user created: login='admin', password='123'")
        
    except Exception as e:
        print(f"❌ Startup error: {e}")
        raise

# ========== ЗАПУСК ==========
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
