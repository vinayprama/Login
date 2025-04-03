from fastapi import FastAPI, Depends, HTTPException, status, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, DateTime, or_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import datetime

# Configuration
DATABASE_URL = "postgresql://postgres:GJjKBMRMAOsUIHqrjCXhwaPXhxagtybU@metro.proxy.rlwy.net:31429/railway"
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# SQLAlchemy setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme (for token based authentication)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# User model
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    security_question: str
    security_answer: str

    @classmethod
    def as_form(cls, 
                username: str = Form(...), 
                email: EmailStr = Form(...), 
                password: str = Form(...), 
                security_question: str = Form(...), 
                security_answer: str = Form(...)):
        return cls(
            username=username, 
            email=email, 
            password=password, 
            security_question=security_question, 
            security_answer=security_answer.lower().strip()
        )
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    security_question = Column(String)
    security_answer = Column(String)

# New model for contact messages
class ContactMessage(Base):
    __tablename__ = "contact_messages"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    message = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

# Create tables if not already present
Base.metadata.create_all(bind=engine)

# Utility functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: datetime.timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(db: Session, identifier: str):
    # identifier can be username or email
    return db.query(User).filter(or_(User.username == identifier, User.email == identifier)).first()

def authenticate_user(db: Session, identifier: str, password: str):
    user = get_user(db, identifier)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(SessionLocal)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user

# Protect docs dependency
def verify_docs_access(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") is None:
            raise HTTPException(status_code=401, detail="Not authorized for docs")
    except JWTError:
        raise HTTPException(status_code=401, detail="Not authorized for docs")

app = FastAPI()

app.mount("/frontend", StaticFiles(directory="frontend",html=True), name="frontend")
# Mount static files for CSS, JS, images, and favicon
app.mount("/static", StaticFiles(directory="static"), name="static")

# Root endpoint - Serve the login page by default
@app.get("/", response_class=HTMLResponse)
def root():
    with open("frontend/login.html", "r") as f:
        return HTMLResponse(content=f.read())


# Override docs route to require authorization
@app.get("/docs", response_class=HTMLResponse)
async def get_documentation(token: str = Depends(verify_docs_access)):
    return get_swagger_ui_html(openapi_url=app.openapi_url, title="Docs")

# Routes for registration, login, reset remain unchanged

@app.post("/register")
def register(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    security_question: str = Form(...),
    security_answer: str = Form(...),
    db: Session = Depends(get_db)
):
    # Check if username or email already exists
    existing_user = db.query(User).filter(or_(User.username == username, User.email == email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    # Hash the password before storing
    hashed_password = get_password_hash(password)

    # Create new user
    user = User(
        username=username,
        email=email,
        hashed_password=hashed_password,
        security_question=security_question,
        security_answer=security_answer.lower().strip()
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    # Redirect to login page
    return RedirectResponse(url="/frontend/login.html", status_code=303)
@app.post("/login")
def login(identifier: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = authenticate_user(db, identifier, password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect credentials")
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id)}, expires_delta=access_token_expires
    )
    # Redirect to welcome page after login, setting a secure cookie with the JWT token.
    response = RedirectResponse(url="/welcome", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response
# Updated welcome page to serve the HTML content from frontend/welcome.html
@app.get("/welcome", response_class=HTMLResponse)
def welcome_page():
    with open("frontend/welcome.html", "r") as f:
        return HTMLResponse(content=f.read())

# @app.post("/reset")
# def reset_password(identifier: str = Form(...), security_answer: str = Form(...),
#                    new_password: str = Form(...), db: Session = Depends(SessionLocal)):
#     user = get_user(db, identifier)
#     if not user:
#         raise HTTPException(status_code=404, detail="User not found")
#     if user.security_answer != security_answer.lower().strip():
#         raise HTTPException(status_code=401, detail="Security answer incorrect")
#     user.hashed_password = get_password_hash(new_password)
#     db.commit()
#     # Redirect to login page after reset
#     return RedirectResponse(url="/login", status_code=303)


@app.post("/reset")
def reset_password(
    identifier: str = Form(...), 
    security_answer: str = Form(...), 
    new_password: str = Form(...), 
    db: Session = Depends(get_db)
):
    print("Kevin")
    user = get_user(db, identifier)  # Function to get user by email or username
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.security_answer.lower().strip() != security_answer.lower().strip():
        raise HTTPException(status_code=401, detail="Security answer incorrect")

    user.hashed_password = get_password_hash(new_password)  # Hash the new password
    db.commit()

    return RedirectResponse(url="/login", status_code=303)

# New endpoint for handling contact form submissions
@app.post("/contact")
def contact_submit(
    name: str = Form(...),
    email: str = Form(...),
    message: str = Form(...),
    db: Session = Depends(SessionLocal)
):
    contact_message = ContactMessage(name=name, email=email, message=message)
    db.add(contact_message)
    db.commit()
    db.refresh(contact_message)
    # Return a JSON response; your JavaScript can then show a success message.
    return JSONResponse(content={"message": "Your message has been received."})

# Serve frontend pages for login, register, reset as before
@app.get("/login", response_class=HTMLResponse)
def login_page():
    with open("frontend/login.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.get("/register", response_class=HTMLResponse)
def register_page():
    with open("frontend/register.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.get("/reset", response_class=HTMLResponse)
def reset_page():
    with open("frontend/reset.html", "r") as f:
        return HTMLResponse(content=f.read())
    

