from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel, Field
from typing import Optional
import secrets
import os
from dotenv import load_dotenv
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta
import sqlite3
from contextlib import contextmanager

load_dotenv()

MODE = os.getenv("MODE", "DEV")
DOCS_USER = os.getenv("DOCS_USER", "admin")
DOCS_PASSWORD = os.getenv("DOCS_PASSWORD", "secret123")
SECRET_KEY = os.getenv("SECRET_KEY", "default-secret-key-change-me")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None if MODE == "PROD" else "/openapi.json")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

security_basic = HTTPBasic()
security_bearer = HTTPBearer()

DATABASE_URL = "todos.db"

def get_db_connection():
    conn = sqlite3.connect(DATABASE_URL)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS todos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                completed BOOLEAN DEFAULT 0
            )
        ''')
        conn.commit()

init_db()

@contextmanager
def db_session():
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = data.copy()
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security_bearer)):
    payload = decode_access_token(credentials.credentials)
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")
    return username

fake_users_db = {}

def auth_user(credentials: HTTPBasicCredentials = Depends(security_basic)):
    user = fake_users_db.get(credentials.username)
    if not user or not verify_password(credentials.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Basic"})
    return credentials.username

def authenticate_docs(credentials: HTTPBasicCredentials = Depends(security_basic)):
    if not (secrets.compare_digest(credentials.username, DOCS_USER) and secrets.compare_digest(credentials.password, DOCS_PASSWORD)):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Basic"})
    return credentials.username

if MODE == "DEV":
    @app.get("/docs", include_in_schema=False)
    def get_docs(_=Depends(authenticate_docs)):
        from fastapi.openapi.docs import get_swagger_ui_html
        return get_swagger_ui_html(openapi_url="/openapi.json", title="API Docs")

    @app.get("/openapi.json", include_in_schema=False)
    def get_openapi(_=Depends(authenticate_docs)):
        from fastapi.openapi.utils import get_openapi
        return get_openapi(title="FastAPI", version="1.0.0", routes=app.routes)

# Задание 6.1 и 6.2
class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=4)

class UserLogin(BaseModel):
    username: str
    password: str

@app.post("/register")
@limiter.limit("1/minute")
def register(request: Request, user: UserRegister):
    if user.username in fake_users_db:
        raise HTTPException(status_code=409, detail="User already exists")
    fake_users_db[user.username] = {"username": user.username, "hashed_password": hash_password(user.password)}
    return {"message": "New user created"}

@app.get("/login")
def login(_=Depends(auth_user)):
    return {"message": "You got my secret, welcome"}

# Задание 6.4 и 6.5
@app.post("/login_jwt")
@limiter.limit("5/minute")
def login_jwt(request: Request, user: UserLogin):
    db_user = fake_users_db.get(user.username)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    if not verify_password(user.password, db_user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Authorization failed")
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/protected_resource")
def protected_resource(current_user: str = Depends(get_current_user)):
    return {"message": f"Access granted for {current_user}"}

# Задание 7.1
def require_role(required_role: str):
    def role_checker(username: str = Depends(get_current_user)):
        user_info = fake_users_db.get(username)
        if not user_info:
            raise HTTPException(status_code=401, detail="User not found")
        role = user_info.get("role", "guest")
        if role != required_role:
            raise HTTPException(status_code=403, detail="Not enough permissions")
        return username
    return role_checker

@app.post("/admin/resource")
def admin_resource(_=Depends(require_role("admin"))):
    return {"message": "Admin access granted"}

@app.get("/user/resource")
def user_resource(_=Depends(require_role("user"))):
    return {"message": "User access granted"}

@app.get("/guest/resource")
def guest_resource(_=Depends(require_role("guest"))):
    return {"message": "Guest access granted"}

# Задание 8.1
@app.post("/register_db")
def register_db(user: UserRegister):
    with db_session() as conn:
        try:
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user.username, user.password))
            return {"message": "User registered successfully!"}
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="Username already exists")

# Задание 8.2
class TodoCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None

class TodoUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    completed: Optional[bool] = None

@app.post("/todos", status_code=201)
def create_todo(todo: TodoCreate):
    with db_session() as conn:
        cursor = conn.execute("INSERT INTO todos (title, description) VALUES (?, ?)", (todo.title, todo.description))
        row = conn.execute("SELECT id, title, description, completed FROM todos WHERE id = ?", (cursor.lastrowid,)).fetchone()
        return dict(row)

@app.get("/todos/{todo_id}")
def get_todo(todo_id: int):
    with db_session() as conn:
        row = conn.execute("SELECT id, title, description, completed FROM todos WHERE id = ?", (todo_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Todo not found")
        return dict(row)

@app.put("/todos/{todo_id}")
def update_todo(todo_id: int, todo: TodoUpdate):
    with db_session() as conn:
        existing = conn.execute("SELECT id FROM todos WHERE id = ?", (todo_id,)).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Todo not found")
        updates = []
        params = []
        if todo.title is not None:
            updates.append("title = ?")
            params.append(todo.title)
        if todo.description is not None:
            updates.append("description = ?")
            params.append(todo.description)
        if todo.completed is not None:
            updates.append("completed = ?")
            params.append(1 if todo.completed else 0)
        if updates:
            params.append(todo_id)
            conn.execute(f"UPDATE todos SET {', '.join(updates)} WHERE id = ?", params)
        row = conn.execute("SELECT id, title, description, completed FROM todos WHERE id = ?", (todo_id,)).fetchone()
        return dict(row)

@app.delete("/todos/{todo_id}")
def delete_todo(todo_id: int):
    with db_session() as conn:
        existing = conn.execute("SELECT id FROM todos WHERE id = ?", (todo_id,)).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Todo not found")
        conn.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
        return {"message": "Todo deleted successfully"}