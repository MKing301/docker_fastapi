import os
from datetime import datetime, timedelta
from typing import Annotated, Optional

import jwt
from dotenv import load_dotenv
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt import PyJWTError
from passlib.context import CryptContext
from sqlalchemy import Boolean, Column, Integer, String, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from logger import logger

load_dotenv()  # loads .env locally, does nothing in prod

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
INITIAL_ADMIN_EMAIL = os.getenv("INITIAL_ADMIN_EMAIL")
INITIAL_ADMIN_PASSWORD = os.getenv("INITIAL_ADMIN_PASSWORD")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is not set")

# --- App & DB Setup ---
app = FastAPI(
    title="FastAPI JWT Auth",
    version="0.1.0",
    description="A demo FastAPI app with JWT authentication.",
)

DATABASE_URL = DATABASE_URL

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
    )
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]


@app.on_event("startup")
def create_initial_admin():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        admin_email = INITIAL_ADMIN_EMAIL
        admin_password = INITIAL_ADMIN_PASSWORD

        if not get_user(db, admin_email):
            hashed_password = get_password_hash(admin_password)
            admin = User(
                email=admin_email,
                hashed_password=hashed_password,
                is_admin=True,
            )
            db.add(admin)
            db.commit()
            db.refresh(admin)
            logger.info(f"Admin user {admin_email} created.")
    finally:
        db.close()


# --- Models ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)


# --- Password hashing ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


# --- OAuth2 & JWT Setup ---
SECRET_KEY = SECRET_KEY
ALGORITHM = ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_user(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()


def authenticate_user(db: Session, email: str, password: str):
    user = get_user(db, email)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user


async def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except PyJWTError:
        raise credentials_exception
    user = get_user(db, email)
    if user is None:
        raise credentials_exception
    return user


# --- Background task ---
def log_message(email: str):
    logger.info(f"User {email} has been created.")


# --- Routes ---
@app.get("/")
async def welcome():
    return {"message": "Welcome to the FastAPI app! Auto-deployed with GitHub Actions."}


@app.get("/health")
async def healthcheck():
    return {"status": "ok"}


@app.post("/token")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = authenticate_user(
        db, form_data.username, form_data.password
    )  # using username intstead of email for consistency with OAuth2PasswordRequestForm
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/user/")
async def create_user(
    email: str,
    password: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Check if user already exists
    existing_user = get_user(db, email)
    if existing_user:
        raise HTTPException(status_code=400, detail="email already registered")

    # Hash the password and create user
    hashed_password = get_password_hash(password)
    new_user = User(email=email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Background task
    background_tasks.add_task(log_message, new_user.email)

    # Generate JWT token immediately
    access_token = create_access_token(data={"sub": new_user.email})

    return {
        "message": f"User {email} created successfully.",
        "access_token": access_token,
        "token_type": "bearer",
    }


@app.get("/users/")
async def get_users(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    users = db.query(User).all()
    # Return only safe fields
    return [{"id": user.id, "email": user.email} for user in users]


@app.get("/me")
async def read_current_user(current_user: User = Depends(get_current_user)):
    return {"id": current_user.id, "email": current_user.email}
