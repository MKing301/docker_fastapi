from dotenv import load_dotenv

from database import Base, SessionLocal, engine
from models import User
from security import generate_random_password, hash_password

config = load_dotenv()


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

            print("✅ Initial admin user created")
            print(f"📧 Email: {admin_email}")
            print(f"🔑 Temporary password: {random_password}")
        else:
            print("ℹ️ Admin user already exists")

    finally:
        db.close()
