# bot.py
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.types import Message
import asyncpg
import os
import hashlib
import secrets
import asyncio

# ========== ПРОВЕРКА ПЕРЕМЕННЫХ ==========
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    print("❌ BOT_TOKEN not set!")
    exit(1)

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print("❌ DATABASE_URL not set!")
    exit(1)

ADMIN_IDS_STR = os.getenv("ADMIN_IDS", "")
ADMIN_IDS = [int(x.strip()) for x in ADMIN_IDS_STR.split(",") if x.strip()]

print(f"🤖 Bot starting...")
print(f"📋 Admin IDs: {ADMIN_IDS}")

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# ========== ИНИЦИАЛИЗАЦИЯ БД ==========
async def init_db():
    try:
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
        print("✅ Database initialized successfully!")
    except Exception as e:
        print(f"❌ Database error: {e}")
        raise

# ========== КОМАНДЫ ==========
@dp.message(Command("start"))
async def start(message: Message):
    await message.answer("🚀 Astra Key Management Bot\n\n"
                        "Commands:\n"
                        "/adduser login password - Create user\n"
                        "/genkey 30 - Generate key\n"
                        "/users - List all users\n"
                        "/ban username - Ban user\n"
                        "/unban username - Unban user")

@dp.message(Command("adduser"))
async def add_user(message: Message):
    if message.from_user.id not in ADMIN_IDS:
        await message.answer("❌ Not authorized!")
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
    except Exception as e:
        await message.answer(f"❌ Error: {e}")
    finally:
        await conn.close()

@dp.message(Command("genkey"))
async def gen_key(message: Message):
    if message.from_user.id not in ADMIN_IDS:
        await message.answer("❌ Not authorized!")
        return
    
    args = message.text.split()
    if len(args) != 2:
        await message.answer("Usage: /genkey 30")
        return
    
    try:
        days = int(args[1])
    except ValueError:
        await message.answer("❌ Invalid number!")
        return
    
    key_code = secrets.token_hex(16)
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        await conn.execute(
            "INSERT INTO keys (key_code, days_valid) VALUES ($1, $2)",
            key_code, days
        )
        await message.answer(
            f"✅ Key generated!\n\n"
            f"🔑 `{key_code}`\n"
            f"📅 Valid for {days} days\n\n"
            f"Use it in the client to login.",
            parse_mode="Markdown"
        )
    except Exception as e:
        await message.answer(f"❌ Error: {e}")
    finally:
        await conn.close()

@dp.message(Command("users"))
async def list_users(message: Message):
    if message.from_user.id not in ADMIN_IDS:
        await message.answer("❌ Not authorized!")
        return
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        users = await conn.fetch("SELECT login, created_at, is_banned FROM users ORDER BY id DESC LIMIT 20")
        
        if not users:
            await message.answer("📋 No users found")
            return
        
        text = "📋 Users List:\n\n"
        for user in users:
            status = "🚫 Banned" if user['is_banned'] else "✅ Active"
            text += f"👤 {user['login']} - {status}\n"
        
        await message.answer(text)
    except Exception as e:
        await message.answer(f"❌ Error: {e}")
    finally:
        await conn.close()

@dp.message(Command("ban"))
async def ban_user(message: Message):
    if message.from_user.id not in ADMIN_IDS:
        await message.answer("❌ Not authorized!")
        return
    
    args = message.text.split()[1:]
    if not args:
        await message.answer("Usage: /ban username")
        return
    
    login = args[0]
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        result = await conn.execute(
            "UPDATE users SET is_banned = TRUE WHERE login = $1",
            login
        )
        if result == "UPDATE 0":
            await message.answer(f"❌ User {login} not found!")
        else:
            await message.answer(f"🚫 User {login} banned!")
    except Exception as e:
        await message.answer(f"❌ Error: {e}")
    finally:
        await conn.close()

@dp.message(Command("unban"))
async def unban_user(message: Message):
    if message.from_user.id not in ADMIN_IDS:
        await message.answer("❌ Not authorized!")
        return
    
    args = message.text.split()[1:]
    if not args:
        await message.answer("Usage: /unban username")
        return
    
    login = args[0]
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        result = await conn.execute(
            "UPDATE users SET is_banned = FALSE WHERE login = $1",
            login
        )
        if result == "UPDATE 0":
            await message.answer(f"❌ User {login} not found!")
        else:
            await message.answer(f"✅ User {login} unbanned!")
    except Exception as e:
        await message.answer(f"❌ Error: {e}")
    finally:
        await conn.close()

# ========== ЗАПУСК ==========
async def main():
    await init_db()
    
    # Убираем старые вебхуки (решаем конфликт)
    try:
        await bot.delete_webhook(drop_pending_updates=True)
        print("✅ Webhook cleared")
    except Exception as e:
        print(f"⚠️ Webhook error: {e}")
    
    print("🤖 Bot is running...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
