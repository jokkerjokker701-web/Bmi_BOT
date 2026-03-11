import imaplib

EMAIL = "javohir95122@gmail.com"
PASSWORD = "abcdeFghijklmnoP".replace(" ", "")

IMAP_SERVER = "imap.gmail.com"
IMAP_PORT = 993

try:
    print("IMAP serverga ulanmoqda...")
    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    print("Ulandi.")

    print("Login qilinmoqda...")
    login_result = mail.login(EMAIL, PASSWORD)
    print("Login natijasi:", login_result)

    print("INBOX ochilmoqda...")
    select_result = mail.select("INBOX")
    print("INBOX natijasi:", select_result)

    mail.logout()
    print("SUCCESS: Gmail IMAP login ishladi.")

except Exception as e:
    print("FAILED:", repr(e))