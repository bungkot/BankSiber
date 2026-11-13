"""Immutable value objects shared by the service and web layers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class User:
    """An authenticated principal."""

    id: int
    username: str
    role: str


@dataclass(frozen=True, slots=True)
class Account:
    """A bank account. Money is stored as integer cents, never as float."""

    id: int
    owner_id: int
    balance_cents: int


@dataclass(frozen=True, slots=True)
class Transaction:
    """A single ledger entry."""

    id: int
    account_id: int
    description: str
    amount_cents: int


def format_cents(cents: int) -> str:
    """Format integer cents as a human readable amount, e.g. ``-1,250.05``."""
    sign = "-" if cents < 0 else ""
    whole, fraction = divmod(abs(cents), 100)
    return f"{sign}{whole:,}.{fraction:02d}"
