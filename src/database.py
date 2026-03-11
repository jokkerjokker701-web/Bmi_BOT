import json
import os
import sqlite3
from typing import Any

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "bot.db")


def get_conn():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS url_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            telegram_id INTEGER,
            username TEXT,
            input_url TEXT NOT NULL,
            final_url TEXT,
            score INTEGER NOT NULL,
            verdict TEXT NOT NULL,
            reasons TEXT
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS connected_chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_user_id INTEGER NOT NULL,
            chat_id INTEGER NOT NULL UNIQUE,
            title TEXT NOT NULL,
            chat_type TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS moderation_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            chat_id INTEGER NOT NULL,
            chat_title TEXT,
            user_id INTEGER,
            username TEXT,
            full_name TEXT,
            input_url TEXT NOT NULL,
            final_url TEXT,
            score INTEGER NOT NULL,
            verdict TEXT NOT NULL,
            action_taken TEXT NOT NULL,
            reasons TEXT
        )
        """
    )

    conn.commit()
    conn.close()


def save_scan_log(
    telegram_id: int,
    username: str,
    input_url: str,
    final_url: str,
    score: int,
    verdict: str,
    reasons: list[str],
):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO url_checks
        (created_at, telegram_id, username, input_url, final_url, score, verdict, reasons)
        VALUES (CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            telegram_id,
            username,
            input_url,
            final_url,
            score,
            verdict,
            json.dumps(reasons, ensure_ascii=False),
        ),
    )
    conn.commit()
    conn.close()


def upsert_connected_chat(
    owner_user_id: int,
    chat_id: int,
    title: str,
    chat_type: str,
    is_active: bool = True,
):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT id FROM connected_chats WHERE chat_id = ?", (chat_id,))
    row = cur.fetchone()

    if row:
        cur.execute(
            """
            UPDATE connected_chats
            SET owner_user_id = ?, title = ?, chat_type = ?, is_active = ?
            WHERE chat_id = ?
            """,
            (owner_user_id, title, chat_type, 1 if is_active else 0, chat_id),
        )
    else:
        cur.execute(
            """
            INSERT INTO connected_chats
            (owner_user_id, chat_id, title, chat_type, is_active)
            VALUES (?, ?, ?, ?, ?)
            """,
            (owner_user_id, chat_id, title, chat_type, 1 if is_active else 0),
        )

    conn.commit()
    conn.close()


def set_chat_active_for_owner(owner_user_id: int, chat_id: int, is_active: bool):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE connected_chats
        SET is_active = ?
        WHERE owner_user_id = ? AND chat_id = ?
        """,
        (1 if is_active else 0, owner_user_id, chat_id),
    )
    conn.commit()
    conn.close()


def set_chat_active_by_chat_id(chat_id: int, is_active: bool):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE connected_chats SET is_active = ? WHERE chat_id = ?",
        (1 if is_active else 0, chat_id),
    )
    conn.commit()
    conn.close()


def get_all_connected_chats_for_owner(owner_user_id: int) -> list[dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT * FROM connected_chats
        WHERE owner_user_id = ?
        ORDER BY title COLLATE NOCASE
        """,
        (owner_user_id,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_active_connected_chats() -> list[dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT * FROM connected_chats
        WHERE is_active = 1
        ORDER BY title COLLATE NOCASE
        """
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_chat_by_id(chat_id: int) -> dict[str, Any] | None:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM connected_chats WHERE chat_id = ?", (chat_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def get_chat_for_owner(owner_user_id: int, chat_id: int) -> dict[str, Any] | None:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT * FROM connected_chats
        WHERE owner_user_id = ? AND chat_id = ?
        """,
        (owner_user_id, chat_id),
    )
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def delete_connected_chat_for_owner(owner_user_id: int, chat_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        DELETE FROM connected_chats
        WHERE owner_user_id = ? AND chat_id = ?
        """,
        (owner_user_id, chat_id),
    )
    conn.commit()
    conn.close()


def save_moderation_action(
    chat_id: int,
    chat_title: str,
    user_id: int | None,
    username: str | None,
    full_name: str | None,
    input_url: str,
    final_url: str,
    score: int,
    verdict: str,
    action_taken: str,
    reasons: list[str],
):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO moderation_actions
        (
            created_at, chat_id, chat_title, user_id, username, full_name,
            input_url, final_url, score, verdict, action_taken, reasons
        )
        VALUES (CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            chat_id,
            chat_title,
            user_id,
            username,
            full_name,
            input_url,
            final_url,
            score,
            verdict,
            action_taken,
            json.dumps(reasons, ensure_ascii=False),
        ),
    )
    conn.commit()
    conn.close()