import os

from typing import Annotated
from fastapi import FastAPI, BackgroundTasks, Depends
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session


app = FastAPI()

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Dependency to get DB session
def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

# Define a simple User model
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)

# Initialize the database
Base.metadata.create_all(bind=engine)


def print_message(name: str):
    print(f"User {name} has been created.")


@app.get("/")
async def healthcheck(db: db_dependency):
    return {"status": "ok"}


@app.get("/user/")
async def get_users(db: db_dependency):
    return db.query(User).all()


@app.post("/user/")
async def create_user(name: str, background_tasks: BackgroundTasks, db: db_dependency):
    new_user = User(name=name)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    background_tasks.add_task(print_message, new_user.name)
    return {"message": "Background task executed."}

