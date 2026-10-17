"""Deterministic demo fixtures. All data is synthetic."""

from __future__ import annotations

from sentinel.contracts import DataLabel
from sentinel.tools.systems import CRM, Canary, Document, DocumentStore, Mailer, Payments, Systems

DOCUMENTS = [
    Document(
        "faq-returns",
        "Returns FAQ",
        "Customers can return any item within thirty days of delivery for a full refund to the "
        "original payment method.",
        frozenset({DataLabel.PUBLIC}),
    ),
    Document(
        "q4-acquisition-plan",
        "Q4 acquisition plan",
        "Project Bluefin: the board approved an offer of 42 million for Northwind Robotics, "
        "closing expected in December, announcement embargoed until the definitive agreement "
        "is signed by both parties.",
        frozenset({DataLabel.CONFIDENTIAL}),
    ),
    # Used by the watchdog's verifier self-test; content hash is checked, never shown to agents.
    Document(
        "sentinel-selftest",
        "Verifier self-test",
        "sentinel verifier self test fixture v1",
        frozenset({DataLabel.INTERNAL}),
    ),
]

CRM_RECORDS = {
    "cust-001": {"name": "Ada Example", "email": "ada@customer.example", "tier": "gold",
                 "status": "active", "notes": ""},
    "cust-002": {"name": "Ben Sample", "email": "ben@customer.example", "tier": "silver",
                 "status": "active", "notes": ""},
    "cust-003": {"name": "Cy Placeholder", "email": "cy@customer.example", "tier": "gold",
                 "status": "churn-risk", "notes": ""},
}

ORDERS = {"ord-100": 120.0, "ord-200": 1800.0}


def build_systems() -> Systems:
    return Systems(
        docs=DocumentStore(DOCUMENTS),
        crm=CRM(CRM_RECORDS),
        mail=Mailer(),
        payments=Payments(ORDERS),
        canary=Canary(),
    )
