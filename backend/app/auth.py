import os
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
from fastapi import Request, HTTPException, status

JWT_SECRET = os.getenv("JWT_SECRET", "change-me")
JWT_ALG = "HS256"
JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "720"))  # 12h
COOKIE_NAME = os.getenv("COOKIE_NAME", "rh_session")

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_pw(pw: str) -> str:
   return pwd.hash(pw)

def verify_pw(plain: str, hashed: str) -> bool:
   return pwd_context.verify(plain, hashed)

def create_token(email: str, role: str) -> str:
   now = datetime.now(timezone.utc)
   exp = now + timedelta(minutes=JWT_EXPIRES_MIN)
   payload = {"sub": email, "role": role, "iat": int(now.timestamp()), "exp": exp}
   return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def read_token_from_cookie(request: Request) -> dict:
   token = request.cookies.get(COOKIE_NAME)
   if not token:
       raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
   try:
       return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
   except JWTError:
       raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")

def require_role(payload: dict, *roles: str):
   role = payload.get("role")
   if role not in roles:
       raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
