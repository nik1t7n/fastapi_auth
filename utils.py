from datetime import timedelta, datetime

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from fastapi import Request

from models import User
from schemas import UserCreate

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class AuthService():
    def __init__(self, db: Session, pwd_context, SECRET_KEY, ALGORITHM):
        self.db = db
        self.pwd_context = pwd_context
        self.SECRET_KEY = SECRET_KEY
        self.ALGORITHM = ALGORITHM

    def get_user_by_username(self, username: str):
        return self.db.query(User).filter(User.username == username).first()

    def create_user(self, user: UserCreate):
        hashed_password = self.pwd_context.hash(user.password)
        db_user = User(username=user.username, hashed_password=hashed_password, role=user.role)
        self.db.add(db_user)
        self.db.commit()
        return "completed creation"

    def authenticate_user(self, username: str, password: str):
        user = self.get_user_by_username(username)
        if not user:
            return False
        if not self.pwd_context.verify(password, user.hashed_password):
            return False
        return user

    def create_access_token(self, data: dict, expires_delta: timedelta | None = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)
        return encoded_jwt

    def verify_token(self, token: str = Depends(oauth2_scheme)):
        exception = HTTPException(status_code=403, detail="Token is invalid or expired")
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            username: str = payload.get("sub")
            role: str = payload.get("role")
            if username is None or role is None:
                raise exception
            return payload
        except JWTError:
            raise exception
