# bot.py
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
import asyncpg
import os
import hashlib
import secrets
import asyncio
import sys
from datetime import datetime

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

bot = Bot(token=BOT_TOKEN)
storage = MemoryStorage()
dp = Dispatcher(storage=storage)

# ========== STATES FOR FSM ==========
class RegistrationStates(StatesGroup):
    waiting_for_login = State()
    waiting_for_password = State()

class KeyRequestStates(StatesGroup):
    waiting_for_key_request = State()

class ChangelogStates(StatesGroup):
    waiting_for_changelog = State()

class BanStates(StatesGroup):
    waiting_for_ban_user = State()

class UnbanStates(StatesGroup):
    waiting_for_unban_user = State()

# ========== ИНИЦИАЛИЗАЦИЯ БД ==========
async def init_db():
    try:
        conn = await asyncpg.connect(DATABASE_URL)
        print("✅ Connected to database")
        
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
        await conn.close()
        print("✅ Database initialized successfully!")
        return True
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False

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

# ========== CALLBACK HANDLERS ==========
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
        await conn.execute(
            "INSERT INTO users (login, password_hash, salt, telegram_id) VALUES ($1, $2, $3, $4)",
            login, password_hash, salt, message.from_user.id
        )
        await message.answer(
            f"✅ Регистрация успешна!\n"
            f"Логин: {login}\n"
            f"Пароль: {password}\n\n"
            f"⚠️ Сохраните эти данные!",
            reply_markup=get_main_keyboard(await is_admin(message.from_user.id))
        )
    except asyncpg.exceptions.UniqueViolationError:
        await message.answer("❌ Пользователь с таким логином уже существует!")
    except Exception as e:
        await message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()
        await state.clear()

@dp.callback_query(lambda c: c.data == "profile")
async def profile_callback(callback: CallbackQuery):
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        user = await conn.fetchrow(
            "SELECT login, is_banned, created_at FROM users WHERE telegram_id = $1",
            callback.from_user.id
        )
        
        if not user:
            await callback.message.answer("❌ Вы не зарегистрированы! Используйте /start для регистрации.")
            await callback.answer()
            return
        
        is_admin = await is_admin(callback.from_user.id)
        status = "👑 Admin" if is_admin else "🎮 Player"
        ban_status = "🚫 Забанен" if user['is_banned'] else "✅ Активен"
        
        text = f"👤 Профиль\n\n"
        text += f"Логин: {user['login']}\n"
        text += f"Статус: {status}\n"
        text += f"Состояние: {ban_status}\n"
        text += f"Зарегистрирован: {user['created_at'].strftime('%d.%m.%Y %H:%M')}\n"
        
        await callback.message.answer(
            text,
            reply_markup=get_main_keyboard(is_admin)
        )
    except Exception as e:
        await callback.message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()
        await callback.answer()

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
        await callback.message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()
        await callback.answer()

@dp.callback_query(lambda c: c.data == "request_key")
async def request_key_callback(callback: CallbackQuery):
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        user = await conn.fetchrow(
            "SELECT id, is_banned FROM users WHERE telegram_id = $1",
            callback.from_user.id
        )
        
        if not user:
            await callback.message.answer("❌ Сначала зарегистрируйтесь!")
            await callback.answer()
            return
        
        if user['is_banned']:
            await callback.message.answer("🚫 Вы забанены и не можете запрашивать ключи!")
            await callback.answer()
            return
        
        # Проверяем, есть ли уже активная заявка
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
        
        # Уведомляем админов
        for admin_id in ADMIN_IDS:
            try:
                await bot.send_message(
                    admin_id,
                    f"📨 Новая заявка на ключ!\n"
                    f"Пользователь: {user['login']}\n"
                    f"ID заявки: {existing or 'новый'}"
                )
            except:
                pass
    except Exception as e:
        await callback.message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()
        await callback.answer()

# ========== ADMIN CALLBACKS ==========
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
            text += f"{status} {user['login']} - {reg_date}\n"
        
        await callback.message.answer(
            text,
            reply_markup=get_main_keyboard(True)
        )
    except Exception as e:
        await callback.message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()
        await callback.answer()

@dp.callback_query(lambda c: c.data == "create_key")
async def create_key_callback(callback: CallbackQuery):
    if not await is_admin(callback.from_user.id):
        await callback.answer("❌ Недостаточно прав!", show_alert=True)
        return
    
    await callback.message.answer("Введите количество дней действия ключа (число):")
    await callback.answer()

@dp.message(Command("genkey"))
async def gen_key(message: Message):
    if not await is_admin(message.from_user.id):
        await message.answer("❌ Недостаточно прав!")
        return
    
    args = message.text.split()
    if len(args) != 2:
        await message.answer("Использование: /genkey 30")
        return
    
    try:
        days = int(args[1])
    except ValueError:
        await message.answer("❌ Некорректное число!")
        return
    
    key_code = secrets.token_hex(16)
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        user = await conn.fetchrow(
            "SELECT id FROM users WHERE telegram_id = $1",
            message.from_user.id
        )
        
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
        await message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()

@dp.callback_query(lambda c: c.data == "ban_player")
async def ban_player_callback(callback: CallbackQuery):
    if not await is_admin(callback.from_user.id):
        await callback.answer("❌ Недостаточно прав!", show_alert=True)
        return
    
    await callback.message.answer("Введите логин игрока для бана:")
    await callback.answer()

@dp.message(Command("ban"))
async def ban_user(message: Message):
    if not await is_admin(message.from_user.id):
        await message.answer("❌ Недостаточно прав!")
        return
    
    args = message.text.split()[1:]
    if not args:
        await message.answer("Использование: /ban логин")
        return
    
    login = args[0]
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        result = await conn.execute(
            "UPDATE users SET is_banned = TRUE WHERE login = $1",
            login
        )
        if result == "UPDATE 0":
            await message.answer(f"❌ Игрок {login} не найден!")
        else:
            await message.answer(
                f"🚫 Игрок {login} забанен!",
                reply_markup=get_main_keyboard(True)
            )
    except Exception as e:
        await message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()

@dp.callback_query(lambda c: c.data == "unban_player")
async def unban_player_callback(callback: CallbackQuery):
    if not await is_admin(callback.from_user.id):
        await callback.answer("❌ Недостаточно прав!", show_alert=True)
        return
    
    await callback.message.answer("Введите логин игрока для разбана:")
    await callback.answer()

@dp.message(Command("unban"))
async def unban_user(message: Message):
    if not await is_admin(message.from_user.id):
        await message.answer("❌ Недостаточно прав!")
        return
    
    args = message.text.split()[1:]
    if not args:
        await message.answer("Использование: /unban логин")
        return
    
    login = args[0]
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        result = await conn.execute(
            "UPDATE users SET is_banned = FALSE WHERE login = $1",
            login
        )
        if result == "UPDATE 0":
            await message.answer(f"❌ Игрок {login} не найден!")
        else:
            await message.answer(
                f"✅ Игрок {login} разбанен!",
                reply_markup=get_main_keyboard(True)
            )
    except Exception as e:
        await message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()

@dp.callback_query(lambda c: c.data == "add_changelog")
async def add_changelog_callback(callback: CallbackQuery):
    if not await is_admin(callback.from_user.id):
        await callback.answer("❌ Недостаточно прав!", show_alert=True)
        return
    
    await callback.message.answer("Введите текст новости для ченжлога:")
    await callback.answer()

@dp.message(Command("addlog"))
async def add_changelog(message: Message):
    if not await is_admin(message.from_user.id):
        await message.answer("❌ Недостаточно прав!")
        return
    
    content = message.text.replace("/addlog", "").strip()
    if not content:
        await message.answer("Использование: /addlog Текст новости")
        return
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        user = await conn.fetchrow(
            "SELECT id FROM users WHERE telegram_id = $1",
            message.from_user.id
        )
        
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
        await message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()

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
            text += f"ID: {req['id']}\n"
            text += f"👤 {req['login']} {status}\n"
            text += f"📅 {req['created_at'].strftime('%d.%m.%Y %H:%M')}\n"
            text += f"---\n"
        
        await callback.message.answer(
            text,
            reply_markup=get_request_keyboard()
        )
    except Exception as e:
        await callback.message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()
        await callback.answer()

@dp.callback_query(lambda c: c.data in ["approve_key", "reject_key"])
async def process_key_request(callback: CallbackQuery):
    if not await is_admin(callback.from_user.id):
        await callback.answer("❌ Недостаточно прав!", show_alert=True)
        return
    
    # В этом упрощенном варианте обрабатываем только последнюю заявку
    # В реальном приложении нужно хранить ID заявки в состоянии
    conn = await asyncpg.connect(DATABASE_URL)
    try:
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
        
        admin = await conn.fetchrow(
            "SELECT id FROM users WHERE telegram_id = $1",
            callback.from_user.id
        )
        
        if callback.data == "approve_key":
            # Генерируем ключ на 30 дней
            key_code = secrets.token_hex(16)
            await conn.execute(
                "INSERT INTO keys (key_code, days_valid, used_by, used_at, created_by) VALUES ($1, $2, $3, $4, $5)",
                key_code, 30, request['user_id'], datetime.now(), admin['id'] if admin else None
            )
            
            await conn.execute(
                "UPDATE key_requests SET status = 'approved', processed_at = NOW(), processed_by = $1 WHERE id = $2",
                admin['id'] if admin else None, request['id']
            )
            
            await callback.message.answer(
                f"✅ Заявка одобрена!\n"
                f"🔑 Ключ: `{key_code}`\n"
                f"Пользователь: {request['login']}"
            )
            
            # Отправляем ключ пользователю
            try:
                await bot.send_message(
                    request['telegram_id'],
                    f"✅ Ваша заявка на ключ одобрена!\n\n"
                    f"🔑 Ключ: `{key_code}`\n"
                    f"📅 Действует 30 дней\n"
                    f"Используйте ключ для активации чита.",
                    parse_mode="Markdown"
                )
            except:
                pass
        else:
            await conn.execute(
                "UPDATE key_requests SET status = 'rejected', processed_at = NOW(), processed_by = $1 WHERE id = $2",
                admin['id'] if admin else None, request['id']
            )
            
            await callback.message.answer(f"❌ Заявка пользователя {request['login']} отклонена.")
            
            try:
                await bot.send_message(
                    request['telegram_id'],
                    "❌ Ваша заявка на ключ отклонена администратором."
                )
            except:
                pass
        
    except Exception as e:
        await callback.message.answer(f"❌ Ошибка: {e}")
    finally:
        await conn.close()
        await callback.answer()

# ========== HELPER FUNCTIONS ==========
async def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS

# ========== ЗАПУСК ==========
async def main():
    print("🚀 Starting bot...")
    
    if not await init_db():
        print("❌ Failed to initialize database!")
        return
    
    try:
        await bot.delete_webhook(drop_pending_updates=True)
        print("✅ Webhook cleared")
    except Exception as e:
        print(f"⚠️ Webhook error: {e}")
    
    print("🤖 Bot is running...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("🛑 Bot stopped")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)
