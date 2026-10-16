# -*- coding: utf-8 -*-
# ============================================================
#   LE HOANG MINH TOOL v20 - FINAL
# ============================================================
import os
import re
import json
import math
import html
import time
import hashlib
import asyncio
import logging
from collections import deque

from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup,
    BotCommand, MenuButtonCommands,
    BotCommandScopeDefault,
    BotCommandScopeAllPrivateChats, BotCommandScopeAllGroupChats,
    BotCommandScopeAllChatAdministrators,
)
from telegram.constants import ParseMode
from telegram.ext import (
    Application, CommandHandler, MessageHandler,
    CallbackQueryHandler, filters, ContextTypes,
)

# ============================================================
#   ⚙️ CẤU HÌNH
# ============================================================
BOT_TOKEN = "8862072402:AAG2T5KXVsaqSQPsQ25sj-HkClBExDVz7Jk"
PORT = int(os.getenv("PORT", 10000))
RENDER_URL = os.getenv("RENDER_EXTERNAL_URL", "").rstrip("/")

ADMIN_IDS = [8852639183]
ADMIN_PHONE = "0372834763"
BRAND_NAME = "LE HOANG MINH"

MASTER_KEY = "leminhios"
SECRET_SALT = "LHM19X9K8M7N6P5Q4W3E2R1"

DATA_DIR = "/data"
if not os.path.exists(DATA_DIR):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
    except Exception:
        DATA_DIR = os.path.dirname(os.path.abspath(__file__))

DB_FILE = os.path.join(DATA_DIR, "users_db.json")
CACHE_FILE = os.path.join(DATA_DIR, "predict_cache.json")

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("telegram").setLevel(logging.WARNING)

LINE = "━━━━━━━━━━━━━"
MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

RATE_LIMIT_WINDOW = 10
RATE_LIMIT_MAX = 10
_rate_bucket = {}


def load_db(path):
    try:
        if not os.path.exists(path):
            return {}
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error("Load DB: " + str(e))
        return {}


def save_db(path, data):
    try:
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except Exception as e:
        logger.error("Save DB: " + str(e))


def left_rotate(x, amount):
    x &= MASK32
    return ((x << amount) | (x >> (32 - amount))) & MASK32


def md5_custom(message):
    T = [int(4294967296 * abs(math.sin(i + 1))) & MASK32 for i in range(64)]
    s = ([7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 +
         [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4)
    orig_len_in_bits = (len(message) * 8) & MASK64
    message += b'\x80'
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'
    message += orig_len_in_bits.to_bytes(8, byteorder='little')
    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for offset in range(0, len(message), 64):
        block = message[offset:offset + 64]
        M = [int.from_bytes(block[i:i + 4], byteorder='little') for i in range(0, 64, 4)]
        a, b, c, d = A, B, C, D
        for i in range(64):
            if i <= 15:
                f = (b & c) | ((~b) & d)
                g = i
            elif i <= 31:
                f = (d & b) | ((~d) & c)
                g = (5 * i + 1) % 16
            elif i <= 47:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | (~d))
                g = (7 * i) % 16
            f = (f + a + T[i] + M[g]) & MASK32
            a = d
            d = c
            c = b
            b = (b + left_rotate(f, s[i])) & MASK32
        A = (A + a) & MASK32
        B = (B + b) & MASK32
        C = (C + c) & MASK32
        D = (D + d) & MASK32
    return (A.to_bytes(4, 'little') + B.to_bytes(4, 'little') +
            C.to_bytes(4, 'little') + D.to_bytes(4, 'little')).hex()


def detect_hash_type(h):
    h = h.strip()
    if re.fullmatch(r"[a-fA-F0-9]{32}", h):
        return "MD5"
    if re.fullmatch(r"[a-fA-F0-9]{64}", h):
        return "SHA-256"
    return None


def azn_predict(hash_input):
    h = hash_input.strip().lower()
    h_bytes = h.encode()

    md5_b = hashlib.md5(h_bytes).hexdigest()
    sha256_b = hashlib.sha256(h_bytes).hexdigest()
    sha1_b = hashlib.sha1(h_bytes).hexdigest()
    sha3_b = hashlib.sha3_256(h_bytes).hexdigest()
    blake2b_b = hashlib.blake2b(h_bytes).hexdigest()
    md5_c = md5_custom(h_bytes)

    combined = (md5_b + sha256_b + sha1_b + sha3_b + blake2b_b + md5_c
                + SECRET_SALT + h)

    score_big = 0
    for i, c in enumerate(combined):
        score_big = (score_big * 131 + ord(c) * (i + 7) + i * 13) & MASK64

    x = score_big
    x ^= x >> 33
    x = (x * 0xff51afd7ed558ccd) & MASK64
    x ^= x >> 33
    x = (x * 0xc4ceb9fe1a85ec53) & MASK64
    x ^= x >> 33
    x = (x * 0xff51afd7ed558ccd) & MASK64
    x ^= x >> 33

    tier = x % 100
    direction = (x >> 8) % 1000
    magnitude = (x >> 16) % 1000

    if tier < 40:
        base = 50.0
        rng = 10.0
    elif tier < 70:
        base = 60.0
        rng = 10.0
    elif tier < 90:
        base = 70.0
        rng = 10.0
    else:
        base = 80.0
        rng = 20.0

    high_pct = base + (magnitude / 1000.0) * rng
    high_pct = round(high_pct, 1)
    if high_pct > 99.9:
        high_pct = 99.9
    if high_pct < 50.0:
        high_pct = 50.0

    low_pct = round(100.0 - high_pct, 1)

    if direction < 500:
        result = "TAI"
        tai_pct = high_pct
        xiu_pct = low_pct
    else:
        result = "XIU"
        tai_pct = low_pct
        xiu_pct = high_pct

    return {
        "result": result,
        "tai": tai_pct,
        "xiu": xiu_pct,
        "type": detect_hash_type(h),
    }


def predict(h):
    h_clean = h.strip().lower()
    if not detect_hash_type(h_clean):
        return {"error": True}

    cache = load_db(CACHE_FILE)
    if h_clean in cache:
        return cache[h_clean]

    res = azn_predict(h_clean)

    cache[h_clean] = res
    if len(cache) > 200000:
        keys = list(cache.keys())[:20000]
        for k in keys:
            del cache[k]
    save_db(CACHE_FILE, cache)

    return res


def esc(t):
    return html.escape(str(t))


def is_vip(user_id):
    users = load_db(DB_FILE)
    uid = str(user_id)
    return uid in users and users[uid].get("vip") is True


def activate_vip(user_id, username="", first_name=""):
    users = load_db(DB_FILE)
    uid = str(user_id)
    users[uid] = {
        "vip": True,
        "username": username,
        "first_name": first_name,
        "activated": time.time(),
    }
    save_db(DB_FILE, users)


def update_user_info(user_id, username, first_name):
    users = load_db(DB_FILE)
    uid = str(user_id)
    if uid in users:
        users[uid]["username"] = username or ""
        users[uid]["first_name"] = first_name or ""
        users[uid]["last_seen"] = time.time()
        save_db(DB_FILE, users)


def is_admin(user_id):
    return user_id in ADMIN_IDS


def rate_limit_ok(user_id):
    now = time.time()
    uid = str(user_id)
    if uid not in _rate_bucket:
        _rate_bucket[uid] = deque()
    bucket = _rate_bucket[uid]
    while bucket and now - bucket[0] > RATE_LIMIT_WINDOW:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_MAX:
        return False
    bucket.append(now)
    return True


async def send_locked_message(update_or_msg):
    text = (
        "🔒 <b>CHUA KICH HOAT</b>\n"
        + LINE + "\n\n"
        "⚠️ Ban can kich hoat de su dung bot!\n\n"
        "📞 Lien he admin de lay key:\n"
        "<code>" + ADMIN_PHONE + "</code>"
    )
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("💬 LIEN HE ADMIN", url="https://zalo.me/" + ADMIN_PHONE)],
    ])
    await update_or_msg.message.reply_text(
        text,
        parse_mode=ParseMode.HTML,
        reply_markup=kb
    )


async def start(update, ctx):
    user = update.effective_user
    if is_vip(user.id):
        update_user_info(user.id, user.username, user.first_name)

    if is_vip(user.id):
        vip_status = "✅ DA KICH HOAT"
    elif is_admin(user.id):
        vip_status = "👑 ADMIN"
    else:
        vip_status = "❌ Chua kich hoat"

    text = (
        "🎯 <b>" + BRAND_NAME + " TOOL</b>\n"
        "⚡ Phan tich MD5 / SHA-256\n"
        + LINE + "\n\n"
        "📥 <b>Gui MD5 (32) hoac SHA-256 (64)</b>\n"
        "→ Bot tu dong phan tich\n"
        "→ Tra ket qua TAI / XIU\n\n"
        + LINE + "\n"
        "🔑 <b>Trang thai:</b> " + vip_status + "\n"
        + LINE + "\n"
        "📋 <b>Lenh:</b>\n"
        "/key - Kich hoat\n"
        "/hotro - Lien he admin"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def cmd_key(update, ctx):
    user = update.effective_user
    args = ctx.args

    if not args:
        text = (
            "🔑 <b>KICH HOAT</b>\n" + LINE + "\n\n"
            "📝 Cu phap:\n"
            "<code>/key MA_KEY</code>"
        )
        await update.message.reply_text(text, parse_mode=ParseMode.HTML)
        return

    input_key = args[0].strip().lower()

    if input_key == MASTER_KEY:
        if is_vip(user.id):
            text = (
                "✅ <b>DA KICH HOAT ROI</b>\n" + LINE + "\n\n"
                "👉 Gui MD5 / SHA-256 de phan tich!"
            )
        else:
            activate_vip(user.id, user.username or "", user.first_name or "")
            text = (
                "✅ <b>KICH HOAT THANH CONG!</b>\n"
                + LINE + "\n\n"
                "🎉 Ban da kich hoat <b>VINH VIEN</b>\n\n"
                "📥 <b>Gui MD5 / SHA-256 de bat dau</b>"
            )
        await update.message.reply_text(text, parse_mode=ParseMode.HTML)
    else:
        text = (
            "❌ <b>KEY SAI!</b>\n" + LINE + "\n\n"
            "📞 Lien he admin: <code>" + ADMIN_PHONE + "</code>"
        )
        await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def cmd_hotro(update, ctx):
    text = (
        "📞 <b>LIEN HE ADMIN</b>\n" + LINE + "\n"
        "• Zalo: <code>" + ADMIN_PHONE + "</code>\n"
        "• SDT: <code>" + ADMIN_PHONE + "</code>"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def handle_hash(update, ctx):
    user = update.effective_user
    text = update.message.text.strip()

    if not is_admin(user.id) and not rate_limit_ok(user.id):
        await update.message.reply_text(
            "⏳ <b>Cham lai!</b> Ban gui qua nhanh.",
            parse_mode=ParseMode.HTML
        )
        return

    if not is_vip(user.id) and not is_admin(user.id):
        await send_locked_message(update)
        return

    update_user_info(user.id, user.username, user.first_name)

    htype = detect_hash_type(text)
    if not htype:
        msg = (
            "❌ <b>SAI DINH DANG!</b>\n" + LINE + "\n\n"
            "Vui long gui:\n"
            "• MD5: <b>32</b> ky tu hex\n"
            "• SHA-256: <b>64</b> ky tu hex\n\n"
            "📝 Vi du:\n"
            "<code>c50d8f23eeffc34b2c07173c8e0b2f47</code>"
        )
        await update.message.reply_text(msg, parse_mode=ParseMode.HTML)
        return

    analyzing_msg = await update.message.reply_text(
        "📊 <b>Dang phan tich...</b>",
        parse_mode=ParseMode.HTML
    )

    res = predict(text)
    await asyncio.sleep(0.6)

    try:
        await analyzing_msg.delete()
    except Exception:
        pass

    if res["result"] == "TAI":
        result_line = "TÀI 🔴"
    else:
        result_line = "XỈU 🔵"

    text_out = (
        "📊 <b>Kết quả phân tích</b>\n"
        + LINE + "\n\n"
        + "🔎 <code>" + esc(text) + "</code>\n"
        + "🧩 Loại: " + res["type"] + "\n\n"
        + "🎯 Kết quả: <b>" + result_line + "</b>\n"
        + "📈 Tỷ lệ: TÀI <b>" + str(res["tai"]) + "%</b> - XỈU <b>" + str(res["xiu"]) + "%</b>"
    )

    await update.message.reply_text(text_out, parse_mode=ParseMode.HTML)


async def error_handler(update, ctx):
    err = str(ctx.error)
    if "Conflict" in err:
        logger.warning("⚠️ Conflict - cho 5s...")
        await asyncio.sleep(5)
        return
    logger.error("Exception: " + err)


async def post_init(app):
    print("=" * 50)
    print("🚀 POST_INIT START")
    print("=" * 50)

    try:
        await app.bot.delete_webhook(drop_pending_updates=True)
        print("✅ Delete webhook OK")
    except Exception as e:
        print("❌ delete_webhook: " + str(e))

    try:
        await app.bot.set_my_name(BRAND_NAME + " TOOL")
        print("✅ Set name OK")
    except Exception as e:
        print("❌ set_my_name: " + str(e))

    try:
        await app.bot.set_my_short_description(
            "Phan tich MD5 / SHA-256\n"
            "Du doan TAI / XIU"
        )
        print("✅ Set short desc OK")
    except Exception as e:
        print("❌ short_desc: " + str(e))

    try:
        await app.bot.set_my_description(
            "LE HOANG MINH TOOL\n\n"
            "Phan tich MD5 / SHA-256\n"
            "Gui hash de du doan TAI / XIU\n\n"
            "Lien he admin de duoc ho tro."
        )
        print("✅ Set desc OK")
    except Exception as e:
        print("❌ desc: " + str(e))

    try:
        await app.bot.delete_my_commands()
        print("✅ Cleared old commands")
    except Exception as e:
        print("⚠️ clear: " + str(e))

    try:
        await app.bot.delete_my_commands(scope=BotCommandScopeAllPrivateChats())
    except Exception:
        pass
    try:
        await app.bot.delete_my_commands(scope=BotCommandScopeAllGroupChats())
    except Exception:
        pass
    try:
        await app.bot.delete_my_commands(scope=BotCommandScopeAllChatAdministrators())
    except Exception:
        pass

    commands = [
        BotCommand("start", "🏠 Bắt đầu"),
        BotCommand("key",   "🔑 Kích hoạt"),
        BotCommand("hotro", "📞 Liên hệ admin"),
    ]

    try:
        await app.bot.set_my_commands(commands, scope=BotCommandScopeDefault())
        print("✅ Set commands OK")
    except Exception as e:
        print("❌ commands: " + str(e))

    try:
        await app.bot.set_chat_menu_button(menu_button=MenuButtonCommands())
        print("✅ Set menu button OK")
    except Exception as e:
        print("❌ menu: " + str(e))

    print("=" * 50)
    print("🎉 POST_INIT DONE")
    print("=" * 50)


def main():
    if not BOT_TOKEN:
        raise SystemExit("Chua co BOT_TOKEN!")

    print("=" * 50)
    print("🚀 STARTING " + BRAND_NAME + " TOOL v20")
    print("DATA_DIR: " + DATA_DIR)
    print("PORT: " + str(PORT))
    print("RENDER_URL: " + (RENDER_URL if RENDER_URL else "(khong co - polling)"))
    print("=" * 50)

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .post_init(post_init)
        .build()
    )

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("key", cmd_key))
    app.add_handler(CommandHandler("hotro", cmd_hotro))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_hash))
    app.add_error_handler(error_handler)

    print("=" * 50)
    print("🎯 BOT READY")
    print("=" * 50)

    if RENDER_URL:
        webhook_url = RENDER_URL + "/" + BOT_TOKEN
        print("🌐 WEBHOOK MODE")
        print("📡 URL: " + webhook_url)
        try:
            app.run_webhook(
                listen="0.0.0.0",
                port=PORT,
                url_path=BOT_TOKEN,
                webhook_url=webhook_url,
                drop_pending_updates=True,
            )
        except Exception as e:
            logger.error("run_webhook err: " + str(e))
            raise
    else:
        print("🔄 POLLING MODE (local)")
        while True:
            try:
                app.run_polling(
                    drop_pending_updates=True,
                    close_loop=False,
                    stop_signals=None,
                )
                break
            except Exception as e:
                err = str(e)
                logger.error("run_polling err: " + err)
                if "Conflict" in err:
                    logger.warning("⚠️ Conflict - cho 10s...")
                    time.sleep(10)
                else:
                    time.sleep(5)


if __name__ == "__main__":
    main()
