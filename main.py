import os
from datetime import timedelta

from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from starlette.middleware.cors import CORSMiddleware

from database import get_db
from schemas import UserCreate
from utils import AuthService

load_dotenv()

app = FastAPI()


def get_auth_service(db: Session = Depends(get_db)):
    return AuthService(db=db, pwd_context=pwd_context, SECRET_KEY=SECRET_KEY, ALGORITHM=ALGORITHM)


origins = [
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))


@app.post("/register")
def register_user(user: UserCreate, auth_service: AuthService = Depends(get_auth_service)):
    try:
        db_user = auth_service.get_user_by_username(user.username)
        if db_user:
            raise HTTPException(status_code=400, detail="Username already registered")
        return auth_service.create_user(user)
    except Exception as e:
        raise e


@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(),
                           auth_service: AuthService = Depends(get_auth_service)):
    try:
        user = auth_service.authenticate_user(form_data.username, form_data.password)
        if not user:
            raise HTTPException(status_code=400, detail="Incorrect username or password")

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = auth_service.create_access_token(data={"sub": user.username, "role": user.role},
                                                        expires_delta=access_token_expires)
        return {"access_token": access_token, "token_type": "bearer", "role": user.role}
    except Exception as e:
        raise e


@app.get("/verify-token/{token}")
async def verify_user_token(token: str, auth_service: AuthService = Depends(get_auth_service)):
    try:
        auth_service.verify_token(token=token)
        return {"message": "Token is valid"}
    except Exception as e:
        raise e


@app.get("/test_user")
async def test_user(auth_service: AuthService = Depends(get_auth_service), token: str = Depends(oauth2_scheme)):
    try:
        payload = auth_service.verify_token(token=token)
        role = payload.get("role")
        if role in ["user", "admin", "superadmin"]:
            return {"message": "User endpoint"}
        else:
            raise HTTPException(status_code=403, detail="Operation not permitted")
    except Exception as e:
        raise e


@app.get("/test_admin")
async def test_admin(auth_service: AuthService = Depends(get_auth_service), token: str = Depends(oauth2_scheme)):
    try:
        payload = auth_service.verify_token(token=token)
        role = payload.get("role")
        if role not in ["admin", "superadmin"]:
            raise HTTPException(status_code=403, detail="Operation not permitted")
        return {"message": "Admin endpoint"}
    except Exception as e:
        raise e


@app.get("/test_superadmin")
async def test_superadmin(auth_service: AuthService = Depends(get_auth_service), token: str = Depends(oauth2_scheme)):
    try:
        payload = auth_service.verify_token(token=token)
        role = payload.get("role")
        if role != "superadmin":
            raise HTTPException(status_code=403, detail="Operation not permitted")
        return {"message": "Superadmin endpoint"}
    except Exception as e:
        raise e
