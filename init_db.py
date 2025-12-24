from dotenv import dotenv_values

from database import Base, SessionLocal, engine
from logger import logger
from models import User
from security import generate_random_password, hash_password

config = dotenv_values(".env")


def init_db():
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        admin_email = config["INITIAL_ADMIN_EMAIL"]

        admin = db.query(User).filter(User.email == admin_email).first()
        if not admin:
            random_password = generate_random_password()

            admin = User(
                email=admin_email,
                password_hash=hash_password(random_password),
                is_admin=True,
            )

            db.add(admin)
            db.commit()

            logger.info("✅ Initial admin user created")
            logger.info(f"📧 Email: {admin_email}")
            logger.info(f"🔑 Temporary password: {random_password}")
        else:
            logger.warning("ℹ️ Admin user already exists")

    finally:
        db.close()
