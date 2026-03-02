import sqlite3
import matplotlib.pyplot as plt
from collections import Counter

DB_PATH = "data/bot.db"

def fetch_levels():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT level FROM url_checks")

    rows = cur.fetchall()

    conn.close()

    return [r[0] for r in rows]


def plot_levels():
    levels = fetch_levels()

    if not levels:
        print("Loglar topilmadi.")
        return

    counts = Counter(levels)

    labels = counts.keys()
    values = counts.values()

    plt.figure()
    plt.bar(labels, values)
    plt.xlabel("Risk darajasi")
    plt.ylabel("Soni")
    plt.title("Phishing Risk Statistikasi")
    plt.show()


if __name__ == "__main__":
    plot_levels()
