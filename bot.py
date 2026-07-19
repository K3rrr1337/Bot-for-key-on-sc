# bot.py
import asyncio
import sys
import os
import hashlib
import secrets
import logging
import fcntl
from datetime import datetime, timedelta
from typing import Optional

from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
import asyncpg

# ========== БЛОКИРОВКА ДЛЯ ПРЕДОТВРАЩЕНИЯ ДВОЙНОГО ЗАПУСКА ==========
try:
    lock_file = open('/tmp/bot.lock', 'w')
    fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
except IOError:
    print("❌ Bot already running! Exiting...")
    sys.exit(0)
except Exception as e:
    print(f"⚠️ Lock error: {e}")

# ========== НАСТРОЙКА ЛОГГИРОВАНИЯ ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ========== ПРОВЕРКА ПЕРЕМЕННЫХ ==========
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    print("❌ BOT_TOKEN not set!")
    sys.exit(1)

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print("❌ DATABASE_URL not set!")
    sys.exit(1)

ADMIN_IDS_STR = os.getenv("ADMIN_IDS", "")
ADMIN_IDS = []
if ADMIN_IDS_STR:
    for x in ADMIN_IDS_STR.split(","):
        try:
            if x.strip():
                ADMIN_IDS.append(int(x.strip()))
        except ValueError:
            print(f"⚠️ Invalid ADMIN_IDS value: {x}")
            pass

print(f"🤖 Bot starting...")
print(f"📋 Admin IDs: {ADMIN_IDS}")

if not ADMIN_IDS:
    print("⚠️ WARNING: No admin IDs set! Some commands will not work.")

# ========== ИНИЦИАЛИЗАЦИЯ ==========
bot = Bot(token=BOT_TOKEN)
storage = MemoryStorage()
dp = Dispatcher(storage=storage)

# ========== STATES FOR FSM ==========
class RegistrationStates(StatesGroup):
    waiting_for_login = State()
    waiting_for_password = State()

class ChangelogStates(StatesGroup):
    waiting_for_changelog = State()

class KeyGenStates(StatesGroup):
    waiting_for_days = State()

class BanStates(StatesGroup):
    waiting_for_username = State()

class UnbanStates(StatesGroup):
    waiting_for_username = State()

# ========== ИНИЦИАЛИЗАЦИЯ БД С МИГРАЦИЕЙ ==========
async def init_db():
    try:
        conn = await asyncpg.connect(DATABASE_URL)
        print("✅ Connected to database")
        
        # Проверяем существование таблицы users
        table_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables 
                WHERE table_name = 'users'
            )
        """)
        
        if not table_exists:
            # Создаем таблицу с нуля
            await conn.execute("""
                CREATE TABLE users (
                    id SERIAL PRIMARY KEY,
                    login VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    salt VARCHAR(50) NOT NULL,
                    is_banned BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    telegram_id BIGINT UNIQUE
                )
            """)
            print("✅ Table 'users' created")
        else:
            # Проверяем наличие колонки telegram_id
            column_exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'users' AND column_name = 'telegram_id'
                )
            """)
            
            if not column_exists:
                await conn.execute("""
                    ALTER TABLE users ADD COLUMN telegram_id BIGINT UNIQUE
                """)
                print("✅ Added 'telegram_id' column to users table")
        
        # Создаем таблицу keys
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
        
        # Проверяем наличие колонки created_by в keys
        column_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'keys' AND column_name = 'created_by'
            )
        """)
        
        if not column_exists:
            await conn.execute("""
                ALTER TABLE keys ADD COLUMN created_by INTEGER REFERENCES users(id)
            """)
            print("✅ Added 'created_by' column to keys table")
        
        # Создаем остальные таблицы
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
        
        await conn.close()
        print("✅ Database initialized successfully!")
        return True
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False

# ========== HELPER FUNCTIONS ==========
async def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS

async def get_user_by_telegram_id(telegram_id: int, conn):
    return await conn.fetchrow(
        "SELECT id, login, is_banned FROM users WHERE telegram_id = $1",
        telegram_id
    )

async def get_user_by_login(login: str, conn):
    return await conn.fetchrow(
        "SELECT id, login, is_banned FROM users WHERE login = $1",
        login
    )

# ========== KEYBOARDS ==========
def get_main_keyboard(is_admin: bool):
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📝 Регистрация", callback_data="register")],
        [InlineKeyboardButton(text="🔑 Запросить ключ", callback_data="request_key")],
        [InlineKeyboardButton(text="📜 Ченжлог", callback_data="view_changelog")],
        [InlineKeyboardButton(text="👤 Профиль", callback_data="profile")]
    ])
    
    if is_admin:
        keyboard.inline_keyboard.extend([
            [InlineKeyboardButton(text="👥 Все игроки", callback_data="view_players")],
            [InlineKeyboardButton(text="🔑 Создать ключ", callback_data="create_key")],
            [InlineKeyboardButton(text="🚫 Бан игрока", callback_data="ban_player")],
            [InlineKeyboardButton(text="✅ Разбан игрока", callback_data="unban_player")],
            [InlineKeyboardButton(text="📝 Добавить в ченжлог", callback_data="add_changelog")],
            [InlineKeyboardButton(text="📋 Заявки на ключи", callback_data="view_requests")]
        ])
    
    return keyboard

def get_request_keyboard():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ Выдать ключ", callback_data="approve_key")],
        [InlineKeyboardButton(text="❌ Отказать", callback_data="reject_key")]
    ])

# ========== COMMANDS ==========
@dp.message(Command("start"))
async def start(message: Message):
    await message.answer(
        "🚀 Astra Key Management Bot\n\n"
        "Добро пожаловать! Используйте кнопки для навигации:",
        reply_markup=get_main_keyboard(await is_admin(message.from_user.id))
    )

@dp.message(Command("menu"))
async def menu(message: Message):
    await start(message)

# ========== REGISTRATION ==========
@dp.callback_query(lambda c: c.data == "register")
async def register_callback(callback: CallbackQuery, state: FSMContext):
    await callback.message.answer("Введите ваш логин:")
    await state.set_state(RegistrationStates.waiting_for_login)
    await callback.answer()

@dp.message(RegistrationStates.waiting_for_login)
async def process_login(message: Message, state: FSMContext):
    await state.update_data(login=message.text)
    await message.answer("Введите ваш пароль:")
    await state.set_state(RegistrationStates.waiting_for_password)

@dp.message(RegistrationStates.waiting_for_password)
async def process_password(message: Message, state: FSMContext):
    data = await state.get_data()
    login = data['login']
    password = message.text
    
    salt = secrets.token_hex(16)
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    password_hash = hash_obj.hex()
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        existing = await conn.fetchrow(
            "SELECT id FROM users WHERE telegram_id = $1 OR login = $2",
            message.from_user.id, login
        )
        
        if existing:
            await message.answer(
                "❌ Вы уже зарегистрированы или логин занят!\n"
                "Используйте /start для просмотра меню."
            )
            await state.clear()
            return
        
        await conn.execute(
            "INSERT INTO users (login, password_hash, salt, telegram_id) VALUES ($1, $2, $3, $4)",
            login, password_hash, salt, message.from_user.id
        )
        await message.answer(
            f"✅ Регистрация успешна!\n"
            f"👤 Логин: {login}\n"
            f"🔑 Пароль: {password}\n\n"
            f"⚠️ Сохраните эти данные!",
            reply_markup=get_main_keyboard(await is_admin(message.from_user.id))
        )
    except asyncpg.exceptions.UniqueViolationError:
        await message.answer("❌ Пользователь с таким логином уже существует!")
    except Exception as e:
        logger.error(f"Registration error: {e}")
        await message.answer(f"❌ Ошибка при регистрации: {str(e)}")
    finally:
        await conn.close()
        await state.clear()

# ========== PROFILE ==========
@dp.callback_query(lambda c: c.data == "profile")
async def profile_callback(callback: CallbackQuery):
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        user = await get_user_by_telegram_id(callback.from_user.id, conn)
        
        if not user:
            await callback.message.answer(
                "❌ Вы не зарегистрированы!\n"
                "Используйте кнопку '📝 Регистрация' для создания аккаунта."
            )
            await callback.answer()
            return
        
        is_admin_user = await is_admin(callback.from_user.id)
        status = "👑 Admin" if is_admin_user else "🎮 Player"
        ban_status = "🚫 Забанен" if user['is_banned'] else "✅ Активен"
        
        keys = await conn.fetch(
            "SELECT key_code, days_valid, used_at FROM keys WHERE used_by = $1 ORDER BY used_at DESC LIMIT 5",
            user['id']
        )
        
        text = f"👤 Профиль\n\n"
        text += f"Логин: {user['login']}\n"
        text += f"Статус: {status}\n"
        text += f"Состояние: {ban_status}\n"
        
        if keys:
            text += f"\n🔑 Активные ключи:\n"
            for key in keys:
                if key['used_at']:
                    expiry = key['used_at'] + timedelta(days=key['days_valid'])
                    days_left = (expiry - datetime.now()).days
                    text += f"• {key['key_code'][:8]}... - {max(0, days_left)} дней\n"
        else:
            text += f"\n🔑 Нет активных ключей"
        
        await callback.message.answer(
            text,
            reply_markup=get_main_keyboard(is_admin_user)
        )
    except Exception as e:
        logger.error(f"Profile error: {e}")
        await callback.message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()
        await callback.answer()

# ========== CHANGELOG ==========
@dp.callback_query(lambda c: c.data == "view_changelog")
async def view_changelog_callback(callback: CallbackQuery):
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        changelogs = await conn.fetch(
            "SELECT content, created_at FROM changelog ORDER BY created_at DESC LIMIT 10"
        )
        
        if not changelogs:
            await callback.message.answer("📭 Ченжлог пока пуст.")
            await callback.answer()
            return
        
        text = "📜 Последние изменения:\n\n"
        for i, log in enumerate(changelogs, 1):
            text += f"{i}. {log['content']}\n"
            text += f"   📅 {log['created_at'].strftime('%d.%m.%Y %H:%M')}\n\n"
        
        await callback.message.answer(
            text,
            reply_markup=get_main_keyboard(await is_admin(callback.from_user.id))
        )
    except Exception as e:
        logger.error(f"Changelog error: {e}")
        await callback.message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()
        await callback.answer()

# ========== REQUEST KEY ==========
@dp.callback_query(lambda c: c.data == "request_key")
async def request_key_callback(callback: CallbackQuery):
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        user = await get_user_by_telegram_id(callback.from_user.id, conn)
        
        if not user:
            await callback.message.answer("❌ Сначала зарегистрируйтесь!")
            await callback.answer()
            return
        
        if user['is_banned']:
            await callback.message.answer("🚫 Вы забанены и не можете запрашивать ключи!")
            await callback.answer()
            return
        
        existing = await conn.fetchrow(
            "SELECT id FROM key_requests WHERE user_id = $1 AND status = 'pending'",
            user['id']
        )
        
        if existing:
            await callback.message.answer("⏳ У вас уже есть активная заявка на получение ключа!")
            await callback.answer()
            return
        
        await conn.execute(
            "INSERT INTO key_requests (user_id) VALUES ($1)",
            user['id']
        )
        
        await callback.message.answer(
            "✅ Заявка на получение ключа отправлена!\n"
            "Ожидайте решения администратора.",
            reply_markup=get_main_keyboard(await is_admin(callback.from_user.id))
        )
        
        for admin_id in ADMIN_IDS:
            try:
                await bot.send_message(
                    admin_id,
                    f"📨 Новая заявка на ключ!\n"
                    f"👤 Пользователь: {user['login']}\n"
                    f"🆔 ID пользователя: {user['id']}"
                )
            except Exception as e:
                logger.error(f"Failed to notify admin {admin_id}: {e}")
    except Exception as e:
        logger.error(f"Request key error: {e}")
        await callback.message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()
        await callback.answer()

# ========== ADMIN: VIEW PLAYERS ==========
@dp.callback_query(lambda c: c.data == "view_players")
async def view_players_callback(callback: CallbackQuery):
    if not await is_admin(callback.from_user.id):
        await callback.answer("❌ Недостаточно прав!", show_alert=True)
        return
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        users = await conn.fetch(
            "SELECT login, is_banned, created_at, telegram_id FROM users ORDER BY created_at DESC"
        )
        
        if not users:
            await callback.message.answer("👥 Нет зарегистрированных игроков.")
            await callback.answer()
            return
        
        text = "👥 Все игроки:\n\n"
        for user in users:
            status = "🚫" if user['is_banned'] else "✅"
            reg_date = user['created_at'].strftime('%d.%m.%Y')
            telegram = f" (TG: {user['telegram_id']})" if user['telegram_id'] else ""
            text += f"{status} {user['login']}{telegram} - {reg_date}\n"
        
        await callback.message.answer(
            text,
            reply_markup=get_main_keyboard(True)
        )
    except Exception as e:
        logger.error(f"View players error: {e}")
        await callback.message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()
        await callback.answer()

# ========== ADMIN: CREATE KEY ==========
@dp.callback_query(lambda c: c.data == "create_key")
async def create_key_callback(callback: CallbackQuery, state: FSMContext):
    if not await is_admin(callback.from_user.id):
        await callback.answer("❌ Недостаточно прав!", show_alert=True)
        return
    
    await callback.message.answer(
        "Введите количество дней действия ключа (число):\n"
        "Пример: 30"
    )
    await state.set_state(KeyGenStates.waiting_for_days)
    await callback.answer()

@dp.message(KeyGenStates.waiting_for_days)
async def process_key_days(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        await message.answer("❌ Недостаточно прав!")
        await state.clear()
        return
    
    try:
        days = int(message.text)
        if days <= 0:
            await message.answer("❌ Количество дней должно быть положительным числом!")
            return
    except ValueError:
        await message.answer("❌ Введите корректное число!")
        return
    
    key_code = secrets.token_hex(16)
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        user = await get_user_by_telegram_id(message.from_user.id, conn)
        
        if user:
            await conn.execute(
                "INSERT INTO keys (key_code, days_valid, created_by) VALUES ($1, $2, $3)",
                key_code, days, user['id']
            )
        else:
            await conn.execute(
                "INSERT INTO keys (key_code, days_valid) VALUES ($1, $2)",
                key_code, days
            )
        
        await message.answer(
            f"✅ Ключ создан!\n\n"
            f"🔑 `{key_code}`\n"
            f"📅 Действует {days} дней\n",
            parse_mode="Markdown",
            reply_markup=get_main_keyboard(True)
        )
    except Exception as e:
        logger.error(f"Gen key error: {e}")
        await message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()
        await state.clear()

# ========== ADMIN: BAN ==========
@dp.callback_query(lambda c: c.data == "ban_player")
async def ban_player_callback(callback: CallbackQuery, state: FSMContext):
    if not await is_admin(callback.from_user.id):
        await callback.answer("❌ Недостаточно прав!", show_alert=True)
        return
    
    await callback.message.answer("Введите логин игрока для бана:")
    await state.set_state(BanStates.waiting_for_username)
    await callback.answer()

@dp.message(BanStates.waiting_for_username)
async def process_ban_user(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        await message.answer("❌ Недостаточно прав!")
        await state.clear()
        return
    
    login = message.text.strip()
    if not login:
        await message.answer("❌ Введите логин!")
        return
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        user = await get_user_by_login(login, conn)
        
        if not user:
            await message.answer(f"❌ Игрок {login} не найден!")
            await state.clear()
            return
        
        if user['is_banned']:
            await message.answer(f"ℹ️ Игрок {login} уже забанен!")
            await state.clear()
            return
        
        await conn.execute(
            "UPDATE users SET is_banned = TRUE WHERE login = $1",
            login
        )
        
        await message.answer(
            f"🚫 Игрок {login} забанен!",
            reply_markup=get_main_keyboard(True)
        )
        
        # Уведомляем пользователя
        user_data = await conn.fetchrow(
            "SELECT telegram_id FROM users WHERE login = $1",
            login
        )
        if user_data and user_data['telegram_id']:
            try:
                await bot.send_message(
                    user_data['telegram_id'],
                    f"🚫 Вы были забанены администратором!"
                )
            except:
                pass
    except Exception as e:
        logger.error(f"Ban error: {e}")
        await message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()
        await state.clear()

# ========== ADMIN: UNBAN ==========
@dp.callback_query(lambda c: c.data == "unban_player")
async def unban_player_callback(callback: CallbackQuery, state: FSMContext):
    if not await is_admin(callback.from_user.id):
        await callback.answer("❌ Недостаточно прав!", show_alert=True)
        return
    
    await callback.message.answer("Введите логин игрока для разбана:")
    await state.set_state(UnbanStates.waiting_for_username)
    await callback.answer()

@dp.message(UnbanStates.waiting_for_username)
async def process_unban_user(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        await message.answer("❌ Недостаточно прав!")
        await state.clear()
        return
    
    login = message.text.strip()
    if not login:
        await message.answer("❌ Введите логин!")
        return
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        user = await get_user_by_login(login, conn)
        
        if not user:
            await message.answer(f"❌ Игрок {login} не найден!")
            await state.clear()
            return
        
        if not user['is_banned']:
            await message.answer(f"ℹ️ Игрок {login} не забанен!")
            await state.clear()
            return
        
        await conn.execute(
            "UPDATE users SET is_banned = FALSE WHERE login = $1",
            login
        )
        
        await message.answer(
            f"✅ Игрок {login} разбанен!",
            reply_markup=get_main_keyboard(True)
        )
        
        # Уведомляем пользователя
        user_data = await conn.fetchrow(
            "SELECT telegram_id FROM users WHERE login = $1",
            login
        )
        if user_data and user_data['telegram_id']:
            try:
                await bot.send_message(
                    user_data['telegram_id'],
                    f"✅ Вы были разбанены администратором!"
                )
            except:
                pass
    except Exception as e:
        logger.error(f"Unban error: {e}")
        await message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()
        await state.clear()

# ========== ADMIN: ADD CHANGELOG ==========
@dp.callback_query(lambda c: c.data == "add_changelog")
async def add_changelog_callback(callback: CallbackQuery, state: FSMContext):
    if not await is_admin(callback.from_user.id):
        await callback.answer("❌ Недостаточно прав!", show_alert=True)
        return
    
    await callback.message.answer(
        "Введите текст новости для ченжлога:\n"
        "Пример: Добавлена новая функция X"
    )
    await state.set_state(ChangelogStates.waiting_for_changelog)
    await callback.answer()

@dp.message(ChangelogStates.waiting_for_changelog)
async def process_changelog(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        await message.answer("❌ Недостаточно прав!")
        await state.clear()
        return
    
    content = message.text.strip()
    if not content:
        await message.answer("❌ Текст не может быть пустым!")
        return
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        user = await get_user_by_telegram_id(message.from_user.id, conn)
        
        if user:
            await conn.execute(
                "INSERT INTO changelog (content, created_by) VALUES ($1, $2)",
                content, user['id']
            )
        else:
            await conn.execute(
                "INSERT INTO changelog (content) VALUES ($1)",
                content
            )
        
        await message.answer(
            f"✅ Новость добавлена в ченжлог!\n\n"
            f"📝 {content}",
            reply_markup=get_main_keyboard(True)
        )
    except Exception as e:
        logger.error(f"Add changelog error: {e}")
        await message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()
        await state.clear()

# ========== ADMIN: VIEW REQUESTS ==========
@dp.callback_query(lambda c: c.data == "view_requests")
async def view_requests_callback(callback: CallbackQuery):
    if not await is_admin(callback.from_user.id):
        await callback.answer("❌ Недостаточно прав!", show_alert=True)
        return
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        requests = await conn.fetch(
            """
            SELECT kr.id, kr.user_id, u.login, u.is_banned, kr.created_at
            FROM key_requests kr
            JOIN users u ON kr.user_id = u.id
            WHERE kr.status = 'pending'
            ORDER BY kr.created_at ASC
            """
        )
        
        if not requests:
            await callback.message.answer("📋 Нет активных заявок на ключи.")
            await callback.answer()
            return
        
        text = "📋 Активные заявки:\n\n"
        for req in requests:
            status = "🚫" if req['is_banned'] else "✅"
            text += f"🆔 ID: {req['id']}\n"
            text += f"👤 {req['login']} {status}\n"
            text += f"📅 {req['created_at'].strftime('%d.%m.%Y %H:%M')}\n"
            text += f"---\n"
        
        await callback.message.answer(
            text,
            reply_markup=get_request_keyboard()
        )
    except Exception as e:
        logger.error(f"View requests error: {e}")
        await callback.message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()
        await callback.answer()

# ========== ADMIN: PROCESS KEY REQUEST ==========
@dp.callback_query(lambda c: c.data in ["approve_key", "reject_key"])
async def process_key_request(callback: CallbackQuery):
    if not await is_admin(callback.from_user.id):
        await callback.answer("❌ Недостаточно прав!", show_alert=True)
        return
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        # Получаем первую активную заявку
        request = await conn.fetchrow(
            """
            SELECT kr.id, kr.user_id, u.login, u.telegram_id
            FROM key_requests kr
            JOIN users u ON kr.user_id = u.id
            WHERE kr.status = 'pending'
            ORDER BY kr.created_at ASC
            LIMIT 1
            """
        )
        
        if not request:
            await callback.message.answer("❌ Нет активных заявок!")
            await callback.answer()
            return
        
        admin = await get_user_by_telegram_id(callback.from_user.id, conn)
        
        if callback.data == "approve_key":
            # Генерируем ключ на 30 дней
            key_code = secrets.token_hex(16)
            await conn.execute(
                "INSERT INTO keys (key_code, days_valid, used_by, used_at) VALUES ($1, $2, $3, $4)",
                key_code, 30, request['user_id'], datetime.now()
            )
            
            await conn.execute(
                "UPDATE key_requests SET status = 'approved', processed_at = NOW(), processed_by = $1 WHERE id = $2",
                admin['id'] if admin else None, request['id']
            )
            
            await callback.message.answer(
                f"✅ Заявка одобрена!\n"
                f"🔑 Ключ: `{key_code}`\n"
                f"👤 Пользователь: {request['login']}\n"
                f"📅 Действует 30 дней",
                parse_mode="Markdown"
            )
            
            # Отправляем ключ пользователю
            if request['telegram_id']:
                try:
                    await bot.send_message(
                        request['telegram_id'],
                        f"✅ Ваша заявка на ключ одобрена!\n\n"
                        f"🔑 Ключ: `{key_code}`\n"
                        f"📅 Действует 30 дней\n"
                        f"Используйте ключ для активации.",
                        parse_mode="Markdown"
                    )
                except Exception as e:
                    logger.error(f"Failed to send key to user: {e}")
        else:
            await conn.execute(
                "UPDATE key_requests SET status = 'rejected', processed_at = NOW(), processed_by = $1 WHERE id = $2",
                admin['id'] if admin else None, request['id']
            )
            
            await callback.message.answer(f"❌ Заявка пользователя {request['login']} отклонена.")
            
            if request['telegram_id']:
                try:
                    await bot.send_message(
                        request['telegram_id'],
                        "❌ Ваша заявка на ключ отклонена администратором."
                    )
                except Exception as e:
                    logger.error(f"Failed to notify user: {e}")
        
    except Exception as e:
        logger.error(f"Process request error: {e}")
        await callback.message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()
        await callback.answer()

# ========== ЗАПУСК ==========
async def main():
    print("🚀 Starting bot...")
    
    if not await init_db():
        print("❌ Failed to initialize database!")
        return
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            await bot.delete_webhook(drop_pending_updates=True)
            print("✅ Webhook cleared")
            break
        except Exception as e:
            print(f"⚠️ Webhook error (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(2)
    
    try:
        me = await bot.get_me()
        print(f"✅ Bot connected: @{me.username} (ID: {me.id})")
    except Exception as e:
        print(f"❌ Failed to connect to Telegram: {e}")
        return
    
    print("🤖 Bot is running...")
    
    while True:
        try:
            await dp.start_polling(
                bot,
                skip_updates=True,
                allowed_updates=["message", "callback_query"]
            )
        except Exception as e:
            logger.error(f"Polling error: {e}")
            print(f"⚠️ Polling crashed, restarting in 5 seconds...")
            await asyncio.sleep(5)
            continue

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("🛑 Bot stopped")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)
