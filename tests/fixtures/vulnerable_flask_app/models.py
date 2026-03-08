"""Data models."""
from dataclasses import dataclass
from typing import Optional


@dataclass
class User:
    id: int
    username: str
    email: str
    password_hash: str
    role: str = "user"


@dataclass
class Item:
    id: int
    name: str
    owner_id: int
    description: Optional[str] = None
