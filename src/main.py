import html
import logging
import os
import re

from dotenv import load_dotenv
from telegram import (
    ChatPermissions,
    KeyboardButton,
    ReplyKeyboardMarkup,
    Update,
)
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from database import ensure_db
from detector import analyze_url, format_result_message

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.INFO,
)

logger = logging.getLogger("phishingbot")

BTN_SCAN = "🔍 Havolani skanerlash"
BTN_CONNECT = "📡 Guruh/Kanallarga ulash"
BTN_HELP = "📌 Yordam"
BTN_NEWS = "📰 Yangiliklar"
BTN_ADMIN = "👤 Admin bilan bog‘lanish"

MAIN_KB = ReplyKeyboardMarkup(
    [
        [KeyboardButton(BTN_SCAN)],
        [KeyboardButton(BTN_CONNECT)],
        [KeyboardButton(BTN_HELP), KeyboardButton(BTN_NEWS)],
        [KeyboardButton(BTN_ADMIN)],
    ],
    resize_keyboard=True,
)

LINK_RE = re.compile(
    r"(https?://[^\s<>\"]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s<>\"]*)?)",
    re.IGNORECASE,
)


def extract_links(text: str):
    matches = LINK_RE.findall(text or "")
    links = []

    for m in matches:
        if not m.startswith("http"):
            m = "https://" + m
        links.append(m)

    # duplicate'larni olib tashlash
    seen = set()
    unique_links = []
    for item in links:
        if item not in seen:
            unique_links.append(item)
            seen.add(item)

    return unique_links


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 Assalomu alaykum!\n\n"
        "Men phishing havolalarni aniqlovchi xavfsizlik botiman.\n\n"
        "📡 Botni guruh yoki kanalga admin qilib qo‘shsangiz "
        "zararli havolalarni avtomatik nazorat qilaman.",
        reply_markup=MAIN_KB,
    )


async def connect_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    bot = await context.bot.get_me()

    text = (
        "📡 <b>Botni guruh yoki kanalga ulash</b>\n\n"
        "1️⃣ Telegramda guruh yoki kanalni oching\n"
        f"2️⃣ Botni qo‘shing: @{bot.username}\n"
        "3️⃣ Botni <b>admin</b> qiling\n\n"
        "Botga quyidagi huquqlarni bering:\n"
        "✔ Delete messages\n"
        "✔ Restrict members\n\n"
        "Shundan keyin bot avtomatik ishlaydi:\n\n"
        "🟢 Xavfsiz link → tegmaydi\n"
        "🔴 Zararli link → xabarni o‘chiradi\n"
        "⛔ Foydalanuvchiga yozish cheklovi qo‘yadi\n"
        "⚠ Guruhga ogohlantirish yuboradi"
    )

    await update.message.reply_text(
        text,
        parse_mode=ParseMode.HTML,
        reply_markup=MAIN_KB,
    )


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📌 Bot imkoniyatlari:\n\n"
        "🔍 havolalarni skan qiladi\n"
        "🚫 phishing havolalarni aniqlaydi\n"
        "🗑 zararli xabarlarni o‘chiradi\n"
        "⛔ foydalanuvchiga yozish cheklovi qo‘yadi\n\n"
        "Bot guruh va kanallarda ishlaydi.",
        reply_markup=MAIN_KB,
    )


async def private_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or ""
    urls = extract_links(text)

    if not urls:
        await update.message.reply_text(
            "❌ Havola topilmadi.",
            reply_markup=MAIN_KB,
        )
        return

    url = urls[0]

    wait = await update.message.reply_text("🔍 Tekshirilmoqda...")

    result = await analyze_url(url)
    msg = format_result_message(result)

    try:
        await wait.delete()
    except Exception:
        pass

    await update.message.reply_text(
        msg,
        parse_mode=ParseMode.MARKDOWN,
        disable_web_page_preview=True,
        reply_markup=MAIN_KB,
    )


async def restrict_user_in_group(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> str:
    """
    Foydalanuvchini guruhda yozolmaydigan qilib cheklaydi.
    """
    message = update.message
    chat = update.effective_chat

    if not message or not chat or not message.from_user or message.from_user.is_bot:
        return "Xabar o‘chirildi"

    try:
        await context.bot.restrict_chat_member(
            chat_id=chat.id,
            user_id=message.from_user.id,
            permissions=ChatPermissions(
                can_send_messages=False,
                can_send_audios=False,
                can_send_documents=False,
                can_send_photos=False,
                can_send_videos=False,
                can_send_video_notes=False,
                can_send_voice_notes=False,
                can_send_polls=False,
                can_send_other_messages=False,
                can_add_web_page_previews=False,
                can_change_info=False,
                can_invite_users=False,
                can_pin_messages=False,
                can_manage_topics=False,
            ),
        )
        return "Foydalanuvchiga guruhda yozish cheklovi qo‘yildi"
    except Exception as exc:
        logger.warning("Foydalanuvchini cheklab bo‘lmadi: %s", exc)
        return "Xabar o‘chirildi, lekin cheklov qo‘yib bo‘lmadi"


def build_restriction_notice(name: str) -> str:
    return (
        "⚠️ <b>Xavfsizlik ogohlantirishi</b>\n\n"
        f"👤 <b>{html.escape(name)}</b> tomonidan yuborilgan xabar xavfsizlik siyosatiga zid deb topildi.\n"
        "Shu sababli xabar o‘chirildi va foydalanuvchiga vaqtincha yozish cheklovi qo‘yildi."
    )


async def group_moderation(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message
    chat = update.effective_chat

    if not message or not chat:
        return

    text = message.text or message.caption or ""
    if not text:
        return

    urls = extract_links(text)
    if not urls:
        return

    worst_result = None
    worst_score = -1

    for url in urls:
        result = await analyze_url(url)
        score = int(result["risk_score"])

        if score > worst_score:
            worst_score = score
            worst_result = result

    if not worst_result:
        return

    # Faqat xavfli linklarda amal bajariladi
    if worst_result["risk_score"] < 60:
        return

    try:
        await message.delete()
    except Exception as exc:
        logger.warning("Xabarni o‘chirib bo‘lmadi: %s", exc)
        return

    offender_name = "Noma'lum foydalanuvchi"
    if message.from_user:
        offender_name = message.from_user.full_name

    action_text = "Xabar o‘chirildi"

    # Kanalda restrict ishlamaydi, guruh/supergroupda ishlaydi
    if chat.type in {"group", "supergroup"}:
        action_text = await restrict_user_in_group(update, context)
    elif chat.type == "channel":
        action_text = "Kanal posti o‘chirildi"

    notice = build_restriction_notice(offender_name)

    try:
        await context.bot.send_message(
            chat_id=chat.id,
            text=notice,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )
    except Exception as exc:
        logger.warning("Ogohlantirish yuborilmadi: %s", exc)

    logger.info(
        "Moderation action | chat=%s | user=%s | score=%s | verdict=%s | action=%s | reasons=%s",
        chat.id,
        offender_name,
        worst_result["risk_score"],
        worst_result["verdict"],
        action_text,
        worst_result["reasons"],
    )


async def private_router(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or ""

    if text == BTN_CONNECT:
        await connect_info(update, context)
        return

    if text == BTN_HELP:
        await help_cmd(update, context)
        return

    if text == BTN_SCAN:
        await update.message.reply_text(
            "Tekshirmoqchi bo‘lgan linkni yuboring.",
            reply_markup=MAIN_KB,
        )
        return

    if text == BTN_NEWS:
        await update.message.reply_text(
            "📰 Yangiliklar bo‘limi keyinroq to‘ldiriladi.",
            reply_markup=MAIN_KB,
        )
        return

    if text == BTN_ADMIN:
        await update.message.reply_text(
            "👤 Admin bilan bog‘lanish bo‘limi keyinroq to‘ldiriladi.",
            reply_markup=MAIN_KB,
        )
        return

    await private_scan(update, context)


def main():
    ensure_db()

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))

    app.add_handler(
        MessageHandler(
            filters.ChatType.PRIVATE & filters.TEXT,
            private_router,
        )
    )

    app.add_handler(
        MessageHandler(
            filters.ChatType.GROUPS & (filters.TEXT | filters.CAPTION),
            group_moderation,
        )
    )

    app.add_handler(
        MessageHandler(
            filters.ChatType.CHANNEL & (filters.TEXT | filters.CAPTION),
            group_moderation,
        )
    )

    logger.info("Bot ishga tushdi...")
    app.run_polling()


if __name__ == "__main__":
    main()