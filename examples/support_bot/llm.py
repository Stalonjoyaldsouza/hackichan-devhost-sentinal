"""LLM wiring."""

import os

from groq import Groq

from tools import issue_refund, lookup_customer, run_report, send_email

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
TOOLS = [lookup_customer, send_email, issue_refund, run_report]
SCHEMAS = [{"type": "function", "function": {"name": t.__name__, "parameters": {}}} for t in TOOLS]


def ask(messages: list[dict]) -> str:
    resp = client.chat.completions.create(
        model="llama-3.3-70b-versatile", messages=messages, tools=SCHEMAS)
    return resp.choices[0].message.content or ""
