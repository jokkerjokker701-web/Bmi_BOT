import os
from dotenv import load_dotenv
from telegram import Bot

load_dotenv()
token = os.getenv("BOT_TOKEN")

if not token:
    raise SystemExit("BOT_TOKEN topilmadi (.env faylni tekshir)")

bot = Bot(token)
bot.delete_webhook(drop_pending_updates=True)
print("OK: webhook o‘chirildi, eski update'lar tozalandi.")
