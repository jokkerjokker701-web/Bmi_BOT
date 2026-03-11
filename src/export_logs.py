import csv
import os
import sqlite3

DB_PATH = os.path.join("data", "bot.db")
OUT_CSV = os.path.join("data", "logs.csv")


def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id, created_at, telegram_id, username, input_url, final_url,
               score, verdict, reasons, vt_stats
        FROM url_checks
        ORDER BY id DESC
        LIMIT 1000
        """
    )
    rows = cur.fetchall()
    headers = [d[0] for d in cur.description]
    conn.close()

    os.makedirs("data", exist_ok=True)
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

    print(f"OK: {OUT_CSV}")


if __name__ == "__main__":
    main()