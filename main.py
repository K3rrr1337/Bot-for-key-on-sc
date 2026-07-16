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

# Подключение к PostgreSQL на Railway
DATABASE_URL = os.getenv("DATABASE_URL")  # Railway сам даст эту переменную

async def get_db():
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        yield conn
    finally:
        await conn.close()

class AuthRequest(BaseModel):
    login: str
    password: str
    key: str

class KeyGenRequest(BaseModel):
    days: int

@app.post("/api/auth")
async def auth(request: AuthRequest, db=Depends(get_db)):
    # Проверяем пользователя
    user = await db.fetchrow(
        "SELECT id, password_hash, salt, is_banned FROM users WHERE login = $1", 
        request.login
    )
    if not user:
        raise HTTPException(401, "Invalid login")
    
    if user['is_banned']:
        raise HTTPException(403, "Banned")
    
    # Проверка пароля
    salt = user['salt']
    input_hash = hashlib.pbkdf2_hmac('sha256', request.password.encode(), salt.encode(), 100000).hex()
    if not hmac.compare_digest(input_hash, user['password_hash']):
        raise HTTPException(401, "Invalid password")
    
    # Проверка ключа
    key = await db.fetchrow(
        "SELECT id, days_valid, used_by FROM keys WHERE key_code = $1", 
        request.key
    )
    if not key:
        raise HTTPException(401, "Invalid key")
    
    if key['used_by'] and key['used_by'] != user['id']:
        raise HTTPException(401, "Key already used")
    
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

@app.post("/api/key/generate")
async def generate_key(request: KeyGenRequest, credentials=Depends(security)):
    # Только админы могут генерировать ключи
    token = credentials.credentials
    # Проверка токена админа...
    
    key_code = secrets.token_hex(16)
    await db.execute(
        "INSERT INTO keys (key_code, days_valid) VALUES ($1, $2)",
        key_code, request.days
    )
    return {"key": key_code, "days": request.days}
