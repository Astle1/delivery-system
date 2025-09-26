# app.py (Final Corrected Version)
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, List

# FastAPI and Security Imports
from fastapi import FastAPI, HTTPException, Depends, status, Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# Pydantic and SQLAlchemy Imports
from pydantic import BaseModel, Field
from sqlalchemy import (
    create_engine, Column, String, DateTime, Enum, ForeignKey, Text
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session

# Hashing, JWT, and Encryption Imports
from passlib.hash import argon2
import jwt
from cryptography.fernet import Fernet

# === Configuration (env vars) ===
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./mailbox.db")
SECRET_KEY = os.getenv("SECRET_KEY")
FERNET_KEY = os.getenv("FERNET_KEY")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))

if not SECRET_KEY or not FERNET_KEY:
    raise SystemExit(
        "ERROR: You must set SECRET_KEY and FERNET_KEY environment variables."
    )

ALGORITHM = "HS256"
fernet = Fernet(FERNET_KEY.encode())

# === FastAPI App Instance and Security Scheme Definition ===
app = FastAPI(title="Mailbox OTP MVP")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# === DB setup ===
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# === Models ===
class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    phone = Column(String, unique=True, nullable=False)
    flat = Column(String, nullable=True)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class PackageStatus:
    PENDING = "pending"
    DELIVERED = "delivered"
    EXPIRED = "expired"
    CANCELLED = "cancelled"

class Package(Base):
    __tablename__ = "packages"
    # ... (rest of the model is the same)
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    courier_name = Column(String, nullable=False)
    courier_package_id = Column(String, nullable=False)
    nickname = Column(String, nullable=True)
    otp_enc = Column(Text, nullable=False)
    status = Column(String, default=PackageStatus.PENDING)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=True)
    used_at = Column(DateTime, nullable=True)
    user = relationship("User")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    # ... (rest of the model is the same)
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    package_id = Column(String, ForeignKey("packages.id"), nullable=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    action = Column(String, nullable=False)
    device_id = Column(String, nullable=True)
    courier_id = Column(String, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    extra = Column(Text, nullable=True)

# === Create DB tables ===
Base.metadata.create_all(bind=engine)

# === Pydantic Schemas ===
# ... (All schemas are the same, no changes needed)
class RegisterIn(BaseModel):
    name: str
    phone: str
    password: str = Field(min_length=6)
    flat: Optional[str] = None

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

# NOTE: LoginIn is no longer needed for the endpoint, but can be kept for clarity
class LoginIn(BaseModel):
    phone: str
    password: str

class PackageIn(BaseModel):
    courier_name: str
    courier_package_id: str
    nickname: Optional[str] = None
    otp: str
    expires_at: Optional[datetime] = None

class PackageUpdate(BaseModel):
    courier_name: Optional[str] = None
    courier_package_id: Optional[str] = None
    nickname: Optional[str] = None
    otp: Optional[str] = None
    expires_at: Optional[datetime] = None

class PackageOut(BaseModel):
    id: str
    courier_name: str
    courier_package_id: str
    nickname: Optional[str]
    status: str
    created_at: datetime
    expires_at: Optional[datetime]
    used_at: Optional[datetime]

class FetchOtpIn(BaseModel):
    phone: str
    order_id: str
    courier_id: Optional[str] = None
    device_id: Optional[str] = None

class FetchOtpOut(BaseModel):
    courier_name: str
    nickname: Optional[str]
    otp: str

# === Helpers ===
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return argon2.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    try:
        return argon2.verify(password, hashed)
    except Exception:
        return False

def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {"sub": subject, "iat": int(now.timestamp()), "exp": int(expire.timestamp())}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def get_current_user_id(token: str = Depends(oauth2_scheme)) -> str:
    user_id = decode_access_token(token)
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return user_id

def encrypt_otp(plain: str) -> str:
    return fernet.encrypt(plain.encode()).decode()

def decrypt_otp(token: str) -> str:
    return fernet.decrypt(token.encode()).decode()

# === Routes ===
@app.post("/register", status_code=201)
def register(data: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter(User.phone == data.phone).first():
        raise HTTPException(status_code=400, detail="Phone already registered")
    user = User(
        name=data.name,
        phone=data.phone,
        flat=data.flat,
        password_hash=hash_password(data.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # ADD THIS AUDIT LOG CODE BACK
    db.add(AuditLog(user_id=user.id, action="register"))
    db.commit()

    return {"ok": True, "user_id": user.id}

@app.post("/login", response_model=TokenOut)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.phone == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    # ADD THIS AUDIT LOG CODE BACK
    db.add(AuditLog(user_id=user.id, action="login"))
    db.commit()

    token = create_access_token(user.id)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/user/packages", response_model=PackageOut)
def add_package(payload: PackageIn, user_id: str = Depends(get_current_user_id), db: Session = Depends(get_db)):
    expires_at = payload.expires_at

    # Normalize incoming expiry to timezone-aware UTC
    if expires_at:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
    else:
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)

    # Prevent duplicates: same user + same courier_package_id that is not cancelled
    existing = db.query(Package).filter(
        Package.user_id == user_id,
        Package.courier_package_id == payload.courier_package_id,
        Package.status != PackageStatus.CANCELLED
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Courier package ID already exists for this user")

    pkg = Package(
        user_id=user_id,
        courier_name=payload.courier_name,
        courier_package_id=payload.courier_package_id,
        nickname=payload.nickname,
        otp_enc=encrypt_otp(payload.otp),
        expires_at=expires_at,
        status=PackageStatus.PENDING
    )
    db.add(pkg)
    db.commit()
    db.refresh(pkg)

    db.add(AuditLog(package_id=pkg.id, user_id=user_id, action="otp_added"))
    db.commit()

    return pkg


@app.get("/user/packages", response_model=List[PackageOut])
def list_packages(user_id: str = Depends(get_current_user_id), db: Session = Depends(get_db)):
    return (
        db.query(Package)
          .filter(Package.user_id == user_id, Package.status != PackageStatus.CANCELLED)
          .all()
    )


@app.put("/user/packages/{package_id}", response_model=PackageOut)
def edit_package(package_id: str, payload: PackageUpdate, user_id: str = Depends(get_current_user_id), db: Session = Depends(get_db)):
    pkg = db.query(Package).filter(Package.id == package_id, Package.user_id == user_id).first()
    if not pkg:
        raise HTTPException(status_code=404, detail="Package not found")
    
    update_data = payload.dict(exclude_unset=True)

    # --- THE FIX IS HERE ---
    if 'expires_at' in update_data and update_data['expires_at']:
        expires_at = update_data['expires_at']
        # If the incoming datetime is naive, make it timezone-aware.
        if expires_at.tzinfo is None:
            update_data['expires_at'] = expires_at.replace(tzinfo=timezone.utc)
    # --- END OF FIX ---

    if 'otp' in update_data:
        pkg.otp_enc = encrypt_otp(update_data['otp'])
        del update_data['otp']
        
    for key, value in update_data.items():
        setattr(pkg, key, value)
        
    db.commit()
    db.refresh(pkg)
    
    db.add(AuditLog(package_id=pkg.id, user_id=user_id, action="otp_edited"))
    db.commit()

    return pkg

@app.delete("/user/packages/{courier_package_id}")
def delete_package(courier_package_id: str, user_id: str = Depends(get_current_user_id), db: Session = Depends(get_db)):
    # Find the package for this user and courier id (any status)
    pkg = db.query(Package).filter(
        Package.courier_package_id == courier_package_id,
        Package.user_id == user_id
    ).first()

    # Not found or already cancelled -> treat as not found
    if not pkg or pkg.status == PackageStatus.CANCELLED:
        raise HTTPException(status_code=404, detail="Package not found")

    # Mark cancelled and audit
    pkg.status = PackageStatus.CANCELLED
    db.add(AuditLog(package_id=pkg.id, user_id=user_id, action="otp_deleted"))
    db.commit()
    return {"ok": True}



# Helpers (add this)
def ensure_aware(dt: Optional[datetime]) -> Optional[datetime]:
    """Return a timezone-aware datetime (assume UTC for naive datetimes)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


@app.post("/delivery/fetch_otp", response_model=FetchOtpOut)
def delivery_fetch_otp(payload: FetchOtpIn, db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.phone == payload.phone).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        now = datetime.now(timezone.utc)

        # Lock the row for update to prevent race conditions
        pkg = (
            db.query(Package)
            .filter(
                Package.user_id == user.id,
                Package.courier_package_id == payload.order_id,
                Package.status == PackageStatus.PENDING
            )
            .with_for_update()
            .first()
        )

        if not pkg:
            raise HTTPException(status_code=404, detail="No pending package found for that order id")

        expires = ensure_aware(pkg.expires_at)
        if expires and expires < now:
            pkg.status = PackageStatus.EXPIRED
            db.commit()
            raise HTTPException(status_code=400, detail="OTP expired")


        otp_plain = decrypt_otp(pkg.otp_enc)
        pkg.status = PackageStatus.DELIVERED
        pkg.used_at = now

        log_entry = AuditLog(
            package_id=pkg.id,
            user_id=user.id,
            action="otp_displayed",
            courier_id=payload.courier_id,
            device_id=payload.device_id
        )
        db.add(log_entry)

        db.commit()  # Commit all changes to the database

        return FetchOtpOut(courier_name=pkg.courier_name, nickname=pkg.nickname, otp=otp_plain)

    except HTTPException:
        db.rollback()  # Rollback on known errors
        raise
    except Exception as e:
        db.rollback()  # Rollback on unexpected errors
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")

@app.get("/health")
def health():
    return {"ok": True}