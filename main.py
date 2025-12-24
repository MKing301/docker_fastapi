from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from database import Base, engine
from deps import get_current_user, get_db
from init_db import init_db
from logger import logger
from models import User
from security import (
    generate_random_password,
    generate_reset_token,
    hash_password,
    verify_reset_token,
)

app = FastAPI()

init_db()

Base.metadata.create_all(bind=engine)


def print_message(name: str):
    logger.info(f"User {name} has been created.")


@app.get("/")
async def healthcheck():
    return {"status": "ok"}


@app.get("/user/")
async def get_users(db: Session = Depends(get_db)):
    return db.query(User).all()


@app.post("/admin/register")
def register_admin(
    email: str, background_tasks: BackgroundTasks, db: Session = Depends(get_db)
):
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    random_password = generate_random_password()
    password_hash = hash_password(random_password)

    user = User(
        email=email,
        password_hash=password_hash,
        is_admin=True,
    )

    background_tasks.add_task(print_message, user.email)

    db.add(user)
    db.commit()

    reset_token = generate_reset_token(email)
    reset_link = f"http://localhost:8000/reset-password?token={reset_token}"

    return {
        "message": "Admin created",
        "temporary_password": random_password,
        "reset_link": reset_link,
    }


@app.post("/reset-password")
def reset_password(token: str, new_password: str, db: Session = Depends(get_db)):
    try:
        email = verify_reset_token(token)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.password_hash = hash_password(new_password)
    db.commit()

    return {"message": "Password reset successful"}


@app.get("/protected")
def protected_route(user: User = Depends(get_current_user)):
    return {
        "email": user.email,
        "is_admin": user.is_admin,
    }
