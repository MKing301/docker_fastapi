import secrets

from argon2 import PasswordHasher
from itsdangerous import URLSafeTimedSerializer

ph = PasswordHasher()
serializer = URLSafeTimedSerializer("SUPER_SECRET_KEY")


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(hash: str, password: str) -> bool:
    return ph.verify(hash, password)


def generate_random_password() -> str:
    return secrets.token_urlsafe(16)


def generate_reset_token(email: str) -> str:
    return serializer.dumps(email)


def verify_reset_token(token: str, max_age=3600) -> str:
    return serializer.loads(token, max_age=max_age)
