import sqlite3
import csv
import os

DB_PATH = os.path.join("data", "bot.db")
OUT_CSV = os.path.join("data", "logs.csv")

def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        SELECT id, created_at, user_id, username,
               input_url, final_url, expanded,
               score, level,
               vt_malicious, vt_suspicious, vt_harmless, vt_undetected
        FROM url_checks
        ORDER BY id DESC
        LIMIT 500
    """)
    rows = cur.fetchall()

    headers = [d[0] for d in cur.description]

    conn.close()

    os.makedirs("data", exist_ok=True)
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)

    print("OK:", OUT_CSV)

if __name__ == "__main__":
    main()
