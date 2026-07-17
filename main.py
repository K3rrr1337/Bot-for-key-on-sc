from fastapi import FastAPI, HTTPException, Depends
import asyncpg
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
import os
from pydantic import BaseModel

app = FastAPI()

DATABASE_URL = os.getenv("DATABASE_URL")

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

@app.get("/")
async def root():
    return {"status": "API is running"}

@app.post("/api/auth")
async def auth(request: AuthRequest, db=Depends(get_db)):
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
        "SELECT id, days_valid, used_by FROM keys WHERE key_code = $1",
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
    
    used_at = await db.fetchval("SELECT used_at FROM keys WHERE id = $1", key['id'])
    expiry = used_at + timedelta(days=key['days_valid'])
    days_left = (expiry - datetime.now()).days
    
    return {
        "success": True,
        "days_left": max(0, days_left),
        "username": request.login,
        "user_id": user['id']
    }

@app.on_event("startup")
async def startup():
    conn = await asyncpg.connect(DATABASE_URL)
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
    await conn.close()
