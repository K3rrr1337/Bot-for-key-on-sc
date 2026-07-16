# bot.py
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
import asyncpg
import os
import hashlib
import secrets

BOT_TOKEN = os.getenv("BOT_TOKEN")
DATABASE_URL = os.getenv("DATABASE_URL")
ADMIN_IDS = [int(x) for x in os.getenv("ADMIN_IDS", "").split(",")]

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

async def init_db():
    conn = await asyncpg.connect(DATABASE_URL)
    # Создаем таблицы если их нет
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

@dp.message(Command("start"))
async def start(message: types.Message):
    await message.answer("🚀 Bot for key management\n\nCommands:\n/adduser login pass\n/genkey 30\n/users\n/ban user")

@dp.message(Command("adduser"))
async def add_user(message: types.Message):
    if message.from_user.id not in ADMIN_IDS:
        return
    
    args = message.text.split()[1:]
    if len(args) != 2:
        await message.answer("Usage: /adduser login password")
        return
    
    login, password = args
    salt = secrets.token_hex(16)
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    password_hash = hash_obj.hex()
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        await conn.execute(
            "INSERT INTO users (login, password_hash, salt) VALUES ($1, $2, $3)",
            login, password_hash, salt
        )
        await message.answer(f"✅ User {login} added successfully!")
    except asyncpg.exceptions.UniqueViolationError:
        await message.answer("❌ User already exists!")
    finally:
        await conn.close()

@dp.message(Command("genkey"))
async def gen_key(message: types.Message):
    if message.from_user.id not in ADMIN_IDS:
        return
    
    args = message.text.split()
    if len(args) != 2:
        await message.answer("Usage: /genkey 30")
        return
    
    days = int(args[1])
    key_code = secrets.token_hex(16)
    
    conn = await asyncpg.connect(DATABASE_URL)
    await conn.execute(
        "INSERT INTO keys (key_code, days_valid) VALUES ($1, $2)",
        key_code, days
    )
    await conn.close()
    
    await message.answer(
        f"✅ Key generated:\n`{key_code}`\nValid for {days} days",
        parse_mode="Markdown"
    )

@dp.message(Command("users"))
async def list_users(message: types.Message):
    if message.from_user.id not in ADMIN_IDS:
        return
    
    conn = await asyncpg.connect(DATABASE_URL)
    users = await conn.fetch("SELECT login, created_at, is_banned FROM users ORDER BY created_at DESC LIMIT 20")
    await conn.close()
    
    if not users:
        await message.answer("No users found")
        return
    
    text = "📋 Users:\n\n"
    for user in users:
        status = "🚫 Banned" if user['is_banned'] else "✅ Active"
        text += f"👤 {user['login']} - {status}\n"
        text += f"   Joined: {user['created_at']}\n\n"
    
    await message.answer(text)

@dp.message(Command("ban"))
async def ban_user(message: types.Message):
    if message.from_user.id not in ADMIN_IDS:
        return
    
    args = message.text.split()[1:]
    if not args:
        await message.answer("Usage: /ban username")
        return
    
    login = args[0]
    conn = await asyncpg.connect(DATABASE_URL)
    await conn.execute("UPDATE users SET is_banned = TRUE WHERE login = $1", login)
    await conn.close()
    
    await message.answer(f"🚫 User {login} banned!")

async def main():
    await init_db()
    await dp.start_polling(bot)

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
