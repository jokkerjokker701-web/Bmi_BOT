import os
import re
import json
import sqlite3
from datetime import datetime
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv
from telegram import (
    Update,
    ReplyKeyboardMarkup,
    KeyboardButton,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
)
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

# =========================
#  CONFIG
# =========================
load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()

# .env:
# ADMIN_LINK=https://t.me/Joxa_5122
# PHISH_NEWS_LINK=https://t.me/Phishing_uzb_bot
ADMIN_LINK = os.getenv("ADMIN_LINK", "https://t.me/Joxa_5122").strip()
PHISH_NEWS_LINK = os.getenv("PHISH_NEWS_LINK", "https://t.me/Phishing_uzb_bot").strip()

DB_PATH = os.path.join("data", "bot.db")

BTN_SCAN = "🔍 Havolani skanerlash"
BTN_HELP = "📌 Yordam"
BTN_NEWS = "📰 Phishing yangiliklari"
BTN_ADMIN = "👤 Admin bilan bog‘lanish"

MAIN_KB = ReplyKeyboardMarkup(
    [
        [KeyboardButton(BTN_SCAN)],
        [KeyboardButton(BTN_HELP), KeyboardButton(BTN_NEWS)],
        [KeyboardButton(BTN_ADMIN)],
    ],
    resize_keyboard=True
)

MODE_KEY = "mode"
MODE_SCAN = "scan"

URL_RE = re.compile(r"(https?://[^\s]+)", re.IGNORECASE)

PHISH_WORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "secure", "security", "update", "unlock", "bonus", "free", "airdrop",
    "wallet", "claim", "password", "support", "restore", "authorize",
    "confirm", "billing", "invoice", "bank", "card", "otp", "2fa"
]

SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly", "rebrand.ly",
    "goo.gl", "ow.ly", "buff.ly", "soo.gd", "shorte.st", "trib.al"
}

# =========================
#  DB HELPERS
# =========================
def ensure_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS url_checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        username TEXT,
        input_url TEXT NOT NULL,
        final_url TEXT,
        score INTEGER NOT NULL,
        level TEXT NOT NULL,
        reasons TEXT
    )
    """)

    cur.execute("PRAGMA table_info(url_checks)")
    cols = {row[1] for row in cur.fetchall()}
    if "reasons" not in cols:
        try:
            cur.execute("ALTER TABLE url_checks ADD COLUMN reasons TEXT")
        except Exception:
            pass

    conn.commit()
    conn.close()


def save_log(username: str, input_url: str, final_url: str, score: int, level: str, reasons: list[str]):
    ensure_db()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO url_checks (created_at, username, input_url, final_url, score, level, reasons)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(timespec="seconds"),
        username or "",
        input_url,
        final_url or "",
        int(score),
        level,
        json.dumps(reasons, ensure_ascii=False)
    ))

    conn.commit()
    conn.close()


# =========================
#  URL HELPERS
# =========================
def extract_urls(text: str) -> list[str]:
    if not text:
        return []
    return URL_RE.findall(text)


def normalize_to_url(text: str) -> str | None:
    """
    kun.uz yuborsa -> https://kun.uz
    https://... bo‘lsa -> o‘sha
    """
    t = (text or "").strip()
    if not t:
        return None

    urls = extract_urls(t)
    if urls:
        return urls[0]

    # oddiy domen/path bo‘lsa (kun.uz, kun.uz/xxx)
    if "." in t and " " not in t:
        if not t.startswith(("http://", "https://")):
            return "https://" + t
        return t

    return None


async def expand_url(url: str, timeout_s: float = 6.0) -> tuple[str, list[str]]:
    notes = []
    final_url = url

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=timeout_s,
            headers={"User-Agent": "Mozilla/5.0"}
        ) as client:
            try:
                r = await client.head(url)
                final_url = str(r.url)
                if final_url != url:
                    notes.append("Short link ochildi (HEAD redirect)")
                return final_url, notes
            except Exception:
                r = await client.get(url)
                final_url = str(r.url)
                if final_url != url:
                    notes.append("Short link ochildi (GET redirect)")
                return final_url, notes

    except Exception:
        notes.append("Short linkni ochib bo‘lmadi (timeout yoki blok)")
        return final_url, notes


def score_url(url: str, final_url: str, expand_notes: list[str]) -> tuple[str, int, list[str]]:
    reasons: list[str] = []
    risk = 0

    def add(points: int, reason: str):
        nonlocal risk
        risk += points
        reasons.append(reason)

    try:
        p = urlparse(final_url or url)
        host = (p.hostname or "").lower()
        scheme = (p.scheme or "").lower()
        path_q = (p.path or "") + ("?" + p.query if p.query else "")
    except Exception:
        return "🔴 Xavfli", 80, ["URL format noto‘g‘ri"]

    if not host:
        return "🔴 Xavfli", 80, ["Domen topilmadi"]

    if scheme != "https":
        add(20, "HTTPS ishlatilmagan")

    if host in SHORTENER_DOMAINS:
        add(25, "Qisqartirilgan (short) link")

    if len(final_url or url) > 90:
        add(10, "URL juda uzun")

    if host.count(".") >= 4:
        add(10, "Subdomainlar juda ko‘p")

    if host.count("-") >= 3:
        add(10, "Domen ichida '-' juda ko‘p")

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        add(25, "Domen o‘rniga IP ishlatilgan")

    low = (final_url or url).lower()
    if any(w in low for w in PHISH_WORDS):
        add(20, "Phishingga xos so‘zlar bor (login/verify/otp/...)")

    if "@" in (final_url or url):
        add(15, "URL ichida '@' bor")

    if "//" in path_q:
        add(10, "URL path ichida ortiqcha '//' bor")

    for n in expand_notes:
        reasons.append(n)
        if "ochib bo‘lmadi" in n:
            add(10, "Redirect ochilmadi (risk oshadi)")

    risk = max(0, min(100, risk))

    safety = 100 - risk
    if safety >= 85:
        level = "🟢 Xavfsiz"
    elif safety >= 70:
        level = "🟡 Shubhali"
    else:
        level = "🔴 Xavfli"

    return level, risk, reasons


# =========================
#  SAFE SEND (EDIT FALLBACK)
# =========================
async def safe_edit_or_send(update: Update, status_msg, text: str):
    MAX = 3500
    parts = [text[i:i + MAX] for i in range(0, len(text), MAX)] or [""]

    try:
        await status_msg.edit_text(parts[0], disable_web_page_preview=True)
    except Exception:
        await update.message.reply_text(parts[0], disable_web_page_preview=True, reply_markup=MAIN_KB)

    for p in parts[1:]:
        await update.message.reply_text(p, disable_web_page_preview=True, reply_markup=MAIN_KB)


# =========================
#  HANDLERS
# =========================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Start bosilganda rejimni tozalaymiz
    context.user_data.pop(MODE_KEY, None)

    text = (
        "👋 Assalomu alaykum!\n\n"
        "Men CyberKo‘z — phishing (firibgar) havolalarni aniqlashga yordam beraman.\n"
        "Quyidagi bo‘limlardan birini tanlang 👇"
    )
    await update.message.reply_text(text, reply_markup=MAIN_KB)


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.pop(MODE_KEY, None)
    text = (
        "📌 Yordam\n\n"
        f"1) {BTN_SCAN} — link yuborasiz, men tekshiraman.\n"
        "2) Linkni shunday yuboring:\n"
        "   • https://example.com\n"
        "   • yoki oddiy: example.com (men o‘zim https:// qo‘shaman)\n\n"
        "⚠️ Eslatma: Natija 100% kafolat emas."
    )
    await update.message.reply_text(text, reply_markup=MAIN_KB)


async def news_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.pop(MODE_KEY, None)
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("📰 Kanalga o‘tish", url=PHISH_NEWS_LINK)]
    ])
    text = "📰 Phishing yangiliklari\n\nPastdagi tugma orqali kanalga o‘ting 👇"
    await update.message.reply_text(text, reply_markup=kb)


async def admin_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.pop(MODE_KEY, None)
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("👤 Adminga yozish", url=ADMIN_LINK)]
    ])
    text = "👤 Admin bilan bog‘lanish\n\nPastdagi tugma orqali yozing 👇"
    await update.message.reply_text(text, reply_markup=kb)


async def scan_prompt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data[MODE_KEY] = MODE_SCAN
    await update.message.reply_text(
        "🔍 Link yuboring\nMisol: https://kun.uz yoki kun.uz",
        reply_markup=MAIN_KB
    )


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return

    text = (update.message.text or "").strip()

    # Menu buttons
    if text == BTN_SCAN:
        return await scan_prompt(update, context)
    if text == BTN_HELP:
        return await help_cmd(update, context)
    if text == BTN_NEWS:
        return await news_cmd(update, context)
    if text == BTN_ADMIN:
        return await admin_cmd(update, context)

    # ✅ Eng muhim o‘zgarish:
    # Agar foydalanuvchi "🔍 Havolani skanerlash" ni bosmagan bo‘lsa,
    # u yozgan narsani (hatto link bo‘lsa ham) tekshirmaymiz.
    if context.user_data.get(MODE_KEY) != MODE_SCAN:
        await update.message.reply_text(
            "📌 Iltimos, pastdagi bo‘limlardan birini tanlang 👇",
            reply_markup=MAIN_KB
        )
        return

    # URL normalize (scan mode ichida)
    url = normalize_to_url(text)
    if not url:
        await update.message.reply_text(
            "❗ Link topilmadi. Iltimos, havola yuboring (kun.uz yoki https://...).",
            reply_markup=MAIN_KB
        )
        return

    status = await update.message.reply_text("🔄 Tekshirilmoqda...", reply_markup=MAIN_KB)

    final_url, expand_notes = await expand_url(url)
    level, risk, reasons = score_url(url, final_url, expand_notes)

    safety = 100 - max(0, min(100, risk))
    username = update.effective_user.username or str(update.effective_user.id)

    try:
        save_log(username, url, final_url, risk, level, reasons)
    except Exception:
        pass

    advice = "⚠️ Tavsiya: shubhali bo‘lsa linkni ochmang, parol/OTP kiritmang."

    result_text = (
        f"🔗 Link: {url}\n"
        f"➡️ Asl manzil: {final_url}\n\n"
        f"📊 Havola xavfsizligi: {safety}%\n"
        f"📝 Izoh: {level}\n\n"
        f"{advice}"
    )

    # ✅ 1 marta tekshiruvdan keyin scan rejimini o‘chiramiz
    context.user_data.pop(MODE_KEY, None)

    await safe_edit_or_send(update, status, result_text)


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE):
    print("ERROR:", context.error)


def main():
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN topilmadi! .env faylni tekshir.")

    ensure_db()

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_error_handler(on_error)

    print("Bot ishga tushdi... (to‘xtatish: CTRL+C)")

    try:
        app.run_polling()
    except KeyboardInterrupt:
        print("Bot to‘xtatildi (CTRL+C).")


if __name__ == "__main__":
    main()