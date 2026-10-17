"""Tools the support agent may call."""

import os
import smtplib
import sqlite3
import subprocess
from email.message import EmailMessage

import requests

DB_PATH = os.environ.get("SUPPORT_DB", "support.db")
SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
PAYMENTS_URL = "https://payments.example.com/v1/refunds"


def tool(fn):
    """Marks a function as callable by the LLM (stand-in for a framework decorator)."""
    return fn


@tool
def lookup_customer(customer_id: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(f"SELECT name, email, ssn FROM customers WHERE id = '{customer_id}'")
    row = cur.fetchone()
    return {"name": row[0], "email": row[1], "ssn": row[2]} if row else {}


@tool
def send_email(to: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["To"], msg["Subject"] = to, subject
    msg.set_content(body)
    with smtplib.SMTP(SMTP_HOST) as server:
        server.send_message(msg)


@tool
def issue_refund(order_id: str, amount: float) -> dict:
    api_key = os.environ["PAYMENTS_API_KEY"]
    resp = requests.post(PAYMENTS_URL, json={"order": order_id, "amount": amount},
                         headers={"Authorization": f"Bearer {api_key}"}, timeout=10)
    return resp.json()


@tool
def run_report(name: str) -> str:
    return subprocess.run(f"./reports/{name}.sh", shell=True, capture_output=True, text=True).stdout


def archive_old_tickets(days: int) -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM tickets WHERE age_days > ?", (days,))
    conn.commit()
