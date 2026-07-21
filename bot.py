# bot.py
import asyncio
import sys
import os
import hashlib
import secrets
import logging
import fcntl
import string
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

class HWIDStates(StatesGroup):
    waiting_for_hwid = State()

# ========== HELPER FUNCTIONS ==========
def generate_promo_code(length: int = 8) -> str:
    """
    Генерирует промокод из заданного количества символов.
    Использует буквы верхнего регистра и цифры для удобства чтения.
    Исключает похожие символы: 0, O, 1, I.
    """
    characters = string.ascii_uppercase + string.digits
    # Убираем похожие символы для удобства
    characters = characters.replace('O', '').replace('0', '').replace('I', '').replace('1', '')
    
    # Генерируем код пока не получим уникальный
    while True:
        code = ''.join(secrets.choice(characters) for _ in range(length))
        # Добавляем проверку на повторяющиеся символы для читаемости
        if len(set(code)) >= length // 2:  # Хотя бы половина символов уникальны
            return code

def hash_hwid(hwid: str) -> str:
    """
    Хеширует HWID для безопасного хранения в БД
    """
    return hashlib.sha256(hwid.encode()).hexdigest()

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
        
        # Создаем таблицу keys с поддержкой HWID
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
        
        # Добавляем колонки для HWID если их нет
        for col in ['hwid_hash', 'is_active', 'activated_at']:
            column_exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'keys' AND column_name = $1
                )
            """, col)
            
            if not column_exists:
                if col == 'hwid_hash':
                    await conn.execute("ALTER TABLE keys ADD COLUMN hwid_hash VARCHAR(255)")
                elif col == 'is_active':
                    await conn.execute("ALTER TABLE keys ADD COLUMN is_active BOOLEAN DEFAULT TRUE")
                elif col == 'activated_at':
                    await conn.execute("ALTER TABLE keys ADD COLUMN activated_at TIMESTAMP")
                print(f"✅ Added '{col}' column to keys table")
        
        # Создаем таблицу для истории HWID
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

async def get_user_active_key(user_id: int, conn) -> Optional[dict]:
    """Получает активный ключ пользователя"""
    return await conn.fetchrow(
        """
        SELECT key_code, days_valid, used_at, hwid_hash, is_active, activated_at
        FROM keys 
        WHERE used_by = $1 AND is_active = TRUE
        ORDER BY used_at DESC 
        LIMIT 1
        """,
        user_id
    )

async def has_active_key(user_id: int, conn) -> bool:
    """Проверяет, есть ли у пользователя активный ключ"""
    result = await conn.fetchval(
        "SELECT COUNT(*) FROM keys WHERE used_by = $1 AND is_active = TRUE",
        user_id
    )
    return result > 0

async def is_hwid_registered(hwid_hash: str, conn) -> bool:
    """Проверяет, зарегистрирован ли HWID в системе"""
    result = await conn.fetchval(
        "SELECT COUNT(*) FROM hwid_history WHERE hwid_hash = $1",
        hwid_hash
    )
    return result > 0

async def get_user_by_hwid(hwid_hash: str, conn) -> Optional[dict]:
    """Получает пользователя по HWID"""
    return await conn.fetchrow(
        """
        SELECT u.id, u.login, u.is_banned, h.key_id
        FROM hwid_history h
        JOIN users u ON h.user_id = u.id
        WHERE h.hwid_hash = $1
        ORDER BY h.created_at DESC
        LIMIT 1
        """,
        hwid_hash
    )

# ========== KEYBOARDS ==========
def get_main_keyboard(is_admin: bool):
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📝 Регистрация", callback_data="register")],
        [InlineKeyboardButton(text="🔑 Запросить ключ", callback_data="request_key")],
        [InlineKeyboardButton(text="🔗 Привязать HWID", callback_data="bind_hwid")],
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
            [InlineKeyboardButton(text="📋 Заявки на ключи", callback_data="view_requests")],
            [InlineKeyboardButton(text="🔍 Проверить HWID", callback_data="check_hwid")]
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
        "Добро пожаловать! Используйте кнопки для навигации:\n"
        "• Регистрация - создайте аккаунт\n"
        "• Запросить ключ - получите ключ доступа\n"
        "• Привязать HWID - привяжите железо\n"
        "• Профиль - информация о вашем аккаунте",
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
            f"⚠️ Сохраните эти данные!\n"
            f"Теперь вы можете запросить ключ и привязать HWID.",
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

# ========== HWID BINDING ==========
@dp.callback_query(lambda c: c.data == "bind_hwid")
async def bind_hwid_callback(callback: CallbackQuery, state: FSMContext):
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        user = await get_user_by_telegram_id(callback.from_user.id, conn)
        
        if not user:
            await callback.message.answer(
                "❌ Вы не зарегистрированы!\n"
                "Сначала пройдите регистрацию."
            )
            await callback.answer()
            return
        
        if user['is_banned']:
            await callback.message.answer("🚫 Вы забанены!")
            await callback.answer()
            return
        
        # Проверяем наличие активного ключа
        has_key = await has_active_key(user['id'], conn)
        if not has_key:
            await callback.message.answer(
                "❌ У вас нет активного ключа!\n"
                "Сначала запросите и активируйте ключ."
            )
            await callback.answer()
            return
        
        await callback.message.answer(
            "🔗 Введите ваш HWID для привязки к аккаунту.\n\n"
            "HWID - это уникальный идентификатор вашего устройства.\n"
            "Пример: HWID-1234567890ABCDEF"
        )
        await state.set_state(HWIDStates.waiting_for_hwid)
    except Exception as e:
        logger.error(f"Bind HWID error: {e}")
        await callback.message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()
        await callback.answer()

@dp.message(HWIDStates.waiting_for_hwid)
async def process_hwid(message: Message, state: FSMContext):
    hwid = message.text.strip()
    
    if len(hwid) < 5:
        await message.answer("❌ HWID слишком короткий! Минимум 5 символов.")
        return
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        user = await get_user_by_telegram_id(message.from_user.id, conn)
        
        if not user:
            await message.answer("❌ Вы не зарегистрированы!")
            await state.clear()
            return
        
        if user['is_banned']:
            await message.answer("🚫 Вы забанены!")
            await state.clear()
            return
        
        # Проверяем наличие активного ключа
        active_key = await get_user_active_key(user['id'], conn)
        if not active_key:
            await message.answer("❌ У вас нет активного ключа!")
            await state.clear()
            return
        
        # Хешируем HWID
        hwid_hash = hash_hwid(hwid)
        
        # Проверяем, не привязан ли этот HWID к другому пользователю
        existing_user = await get_user_by_hwid(hwid_hash, conn)
        if existing_user and existing_user['id'] != user['id']:
            await message.answer(
                "❌ Этот HWID уже привязан к другому аккаунту!\n"
                "Каждый HWID может быть использован только один раз."
            )
            await state.clear()
            return
        
        # Проверяем, не привязан ли уже пользователь к другому HWID
        existing_hwid = await conn.fetchrow(
            "SELECT hwid_hash FROM hwid_history WHERE user_id = $1",
            user['id']
        )
        
        if existing_hwid:
            await message.answer(
                f"❌ К вашему аккаунту уже привязан HWID!\n"
                f"Один аккаунт = один HWID.\n"
                f"Для смены HWID обратитесь к администратору."
            )
            await state.clear()
            return
        
        # Привязываем HWID
        await conn.execute(
            """
            INSERT INTO hwid_history (user_id, hwid_hash, key_id) 
            VALUES ($1, $2, $3)
            """,
            user['id'], hwid_hash, active_key['id']
        )
        
        # Обновляем ключ
        await conn.execute(
            "UPDATE keys SET hwid_hash = $1, activated_at = NOW() WHERE id = $2",
            hwid_hash, active_key['id']
        )
        
        await message.answer(
            f"✅ HWID успешно привязан!\n\n"
            f"🔗 HWID: `{hwid[:10]}...`\n"
            f"👤 Аккаунт: {user['login']}\n"
            f"🔑 Ключ: {active_key['key_code']}\n\n"
            f"⚠️ Важно: HWID привязан к этому аккаунту и не может быть изменен без помощи администратора.",
            parse_mode="Markdown",
            reply_markup=get_main_keyboard(await is_admin(message.from_user.id))
        )
        
    except Exception as e:
        logger.error(f"Process HWID error: {e}")
        await message.answer(f"❌ Ошибка при привязке HWID: {str(e)}")
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
        
        # Получаем информацию о HWID
        hwid_info = await conn.fetchrow(
            "SELECT hwid_hash, created_at FROM hwid_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
            user['id']
        )
        
        # Получаем активный ключ
        active_key = await get_user_active_key(user['id'], conn)
        
        text = f"👤 Профиль\n\n"
        text += f"Логин: {user['login']}\n"
        text += f"Статус: {status}\n"
        text += f"Состояние: {ban_status}\n"
        
        if hwid_info:
            text += f"🔗 HWID: Привязан ✅\n"
            text += f"📅 Привязан: {hwid_info['created_at'].strftime('%d.%m.%Y %H:%M')}\n"
        else:
            text += f"🔗 HWID: Не привязан ❌\n"
        
        if active_key:
            expiry = active_key['used_at'] + timedelta(days=active_key['days_valid'])
            days_left = (expiry - datetime.now()).days
            text += f"\n🔑 Активный ключ: {active_key['key_code']}\n"
            text += f"📅 Действует до: {expiry.strftime('%d.%m.%Y')}\n"
            text += f"⏳ Осталось: {max(0, days_left)} дней\n"
            
            if active_key['hwid_hash']:
                text += f"🔗 Привязан к HWID: Да\n"
            else:
                text += f"🔗 Привязан к HWID: Нет\n"
        else:
            text += f"\n🔑 Нет активного ключа\n"
        
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
        
        # Проверяем, есть ли уже активный ключ
        has_key = await has_active_key(user['id'], conn)
        if has_key:
            await callback.message.answer(
                "❌ У вас уже есть активный ключ!\n"
                "Один аккаунт может иметь только один активный ключ."
            )
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
            """
            SELECT u.login, u.is_banned, u.created_at, u.telegram_id,
                   COUNT(k.id) as key_count,
                   EXISTS(SELECT 1 FROM hwid_history h WHERE h.user_id = u.id) as has_hwid
            FROM users u
            LEFT JOIN keys k ON u.id = k.used_by AND k.is_active = TRUE
            GROUP BY u.id
            ORDER BY u.created_at DESC
            """
        )
        
        if not users:
            await callback.message.answer("👥 Нет зарегистрированных игроков.")
            await callback.answer()
            return
        
        text = "👥 Все игроки:\n\n"
        for user in users:
            status = "🚫" if user['is_banned'] else "✅"
            hwid_status = "🔗" if user['has_hwid'] else "❌"
            reg_date = user['created_at'].strftime('%d.%m.%Y')
            telegram = f" (TG: {user['telegram_id']})" if user['telegram_id'] else ""
            text += f"{status} {hwid_status} {user['login']}{telegram} - {reg_date}\n"
            text += f"   Ключей: {user['key_count']}\n"
        
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
    
    # Генерируем промокод из 8 символов
    key_code = generate_promo_code(8)
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        # Проверяем уникальность ключа
        existing = await conn.fetchrow(
            "SELECT id FROM keys WHERE key_code = $1",
            key_code
        )
        
        # Если ключ уже существует, генерируем новый
        while existing:
            key_code = generate_promo_code(8)
            existing = await conn.fetchrow(
                "SELECT id FROM keys WHERE key_code = $1",
                key_code
            )
        
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
            f"📅 Действует {days} дней\n\n"
            f"💡 Ключ состоит из 8 символов (буквы и цифры)\n"
            f"⚠️ Ключ будет активирован при выдаче пользователю.",
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
        
        # Деактивируем все ключи пользователя
        await conn.execute(
            "UPDATE keys SET is_active = FALSE WHERE used_by = $1",
            user['id']
        )
        
        await message.answer(
            f"🚫 Игрок {login} забанен!\n"
            f"Все его ключи деактивированы.",
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
                    f"🚫 Вы были забанены администратором!\n"
                    f"Все ваши ключи деактивированы."
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
            await message.answer(f"❌ Игрок
