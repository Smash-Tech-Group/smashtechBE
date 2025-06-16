from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta
import jwt
import bcrypt
from sqlalchemy.orm import Session
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from typing import List, Optional
import os
import uuid
from pathlib import Path
from fastapi.responses import FileResponse


# Import database components
from app.database.db import SessionLocal, engine, get_db
from app.models.model import Base, User, Job, Application


# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Job Management API")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT Configuration
SECRET_KEY = "your-secret-key-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# APP URL Configuration - Update this with your actual domain
APP_URL = "http://127.0.0.1:8000"

# Security
security = HTTPBearer()

# Pydantic Models
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# Updated Job Models
class JobBase(BaseModel):
    title: str
    description: str
    requirements: Optional[str] = None
    location: str
    job_type: str 
    salary_range: Optional[str] = None
    application_deadline: Optional[datetime] = None
    is_active: bool = True

class JobCreate(JobBase):
    pass

class JobUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    requirements: Optional[str] = None
    location: Optional[str] = None
    job_type: Optional[str] = None 
    salary_range: Optional[str] = None
    application_deadline: Optional[datetime] = None
    is_active: Optional[bool] = None

class JobResponse(BaseModel):
    id: int
    title: str
    description: str
    requirements: Optional[str] = None
    location: str
    job_type: str
    salary_range: Optional[str] = None
    application_deadline: Optional[datetime] = None
    is_active: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

# Application Models
class ApplicationBase(BaseModel):
    job_id: int
    name: str
    email: EmailStr
    phone: str
    experience: str
    cover_letter: str


class StatusUpdate(BaseModel):
    status: str


# Updated Application Models
class ApplicationCreate(BaseModel):
    job_id: int
    first_name: str
    middle_name: Optional[str] = None
    last_name: str
    dob: str  # Will be converted to datetime
    state_of_origin: str
    address: str
    email: EmailStr
    phone: str
    portfolio: Optional[str] = None
    social_link: str
    experience: str
    cover_letter: str

class ApplicationResponse(BaseModel):
    id: int
    job_id: int
    first_name: str
    middle_name: Optional[str] = None
    last_name: str
    dob: datetime
    state_of_origin: str
    address: str
    email: str
    phone: str
    portfolio: Optional[str] = None
    social_link: str
    experience: str
    cover_letter: str
    cv_filename: Optional[str] = None  # This will now contain the full URL
    applied_at: datetime
    status: str
    
    class Config:
        from_attributes = True



class ApplicationWithJob(ApplicationResponse):
    job: JobResponse
    

# Directory for storing uploaded CVs
UPLOAD_DIR = Path("uploads/cvs")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Helper function to generate CV URL
def generate_cv_url(username: str, filename: str) -> str:
    """Generate full URL for CV file"""
    return f"{APP_URL}/{username}/cv/{filename}"

# Auth functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = db.query(User).filter(User.username == username).first()
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Auth endpoints
@app.post("/register", response_model=dict)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    # Check if user exists
    db_user = db.query(User).filter(
        (User.username == user.username) | (User.email == user.email)
    ).first()
    
    if db_user:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    # Create new user
    hashed_password = hash_password(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        password=hashed_password
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return {"message": "User created successfully"}

@app.post("/login", response_model=Token)
async def login(user: UserLogin, db: Session = Depends(get_db)):
    # Find user
    db_user = db.query(User).filter(User.username == user.username).first()
    
    if not db_user or not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create token
    access_token = create_access_token(data={"sub": db_user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# Job endpoints
@app.get("/")
async def root():
    return {"message": "Job Management API is running"}



@app.get("/jobs/", response_model=List[JobResponse])
def get_jobs(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Get all active jobs"""
    jobs = db.query(Job).filter(Job.is_active == True).offset(skip).limit(limit).all()
    return jobs


@app.get("/jobs/{job_id}", response_model=JobResponse)
def get_job(job_id: int, db: Session = Depends(get_db)):
    """Get a specific job by ID"""
    job = db.query(Job).filter(Job.id == job_id).first()
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.post("/jobs/", response_model=JobResponse)
def create_job(job: JobCreate, db: Session = Depends(get_db)):
    """Create a new job posting (Admin only)"""
    # Validate job_type
    valid_job_types = ["Full Time", "Part Time", "Contract", "Remote", "Hybrid", "Internship"]
    if job.job_type not in valid_job_types:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid job_type. Must be one of: {', '.join(valid_job_types)}"
        )
    
    db_job = Job(**job.dict())
    db.add(db_job)
    db.commit()
    db.refresh(db_job)
    return db_job



@app.put("/jobs/{job_id}", response_model=JobResponse)
def update_job(job_id: int, job_update: JobUpdate, db: Session = Depends(get_db)):
    """Update a job posting (Admin only)"""
    db_job = db.query(Job).filter(Job.id == job_id).first()
    if db_job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Validate job_type if provided
    if job_update.job_type is not None:
        valid_job_types = ["Full Time", "Part Time", "Contract", "Remote", "Hybrid", "Internship"]
        if job_update.job_type not in valid_job_types:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid job_type. Must be one of: {', '.join(valid_job_types)}"
            )
    
    update_data = job_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_job, field, value)
    
    db.commit()
    db.refresh(db_job)
    return db_job


@app.delete("/jobs/{job_id}")
def delete_job(job_id: int, db: Session = Depends(get_db)):
    """Delete a job posting (Admin only)"""
    db_job = db.query(Job).filter(Job.id == job_id).first()
    if db_job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    
    db.delete(db_job)
    db.commit()
    return {"message": "Job deleted successfully"}


# NEW: Get all applications endpoint
@app.get("/applications-list/", response_model=List[ApplicationWithJob])
def get_all_applications(skip: int = 0, limit: int = 100, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get all applications (Admin only)"""
    applications = db.query(Application).offset(skip).limit(limit).all()
    return applications


# NEW: Get applications for a specific job
@app.get("/jobs/{job_id}/applications", response_model=List[ApplicationResponse])
def get_job_applications(job_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get all applications for a specific job (Admin only)"""
    # Verify job exists
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    applications = db.query(Application).filter(Application.job_id == job_id).all()
    return applications


@app.post("/applications/", response_model=ApplicationResponse)
async def create_application(
    job_id: int = Form(...),
    first_name: str = Form(...),
    middle_name: Optional[str] = Form(None),
    last_name: str = Form(...),
    dob: str = Form(...),
    state_of_origin: str = Form(...),
    address: str = Form(...),
    email: str = Form(...),
    phone: str = Form(...),
    portfolio: Optional[str] = Form(None),
    social_link: str = Form(...),
    experience: str = Form(...),
    cover_letter: str = Form(...),
    cv_file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db)
):
    """Submit a job application"""
    
    # Verify job exists and is active
    job = db.query(Job).filter(Job.id == job_id, Job.is_active == True).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found or no longer active")
    
    # Check if user already applied for this job
    existing_application = db.query(Application).filter(
        Application.job_id == job_id,
        Application.email == email
    ).first()
    
    if existing_application:
        raise HTTPException(
            status_code=400, 
            detail="You have already applied for this position"
        )
    
    # Convert date string to datetime
    try:
        dob_datetime = datetime.strptime(dob, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")
    
    cv_url = None
    if cv_file:
        # Validate file type and size
        allowed_types = ['application/pdf', 'application/msword', 
                        'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
        if cv_file.content_type not in allowed_types:
            raise HTTPException(
                status_code=400, 
                detail="Only PDF, DOC, and DOCX files are allowed"
            )
        
        # Check file size (5MB limit)
        if cv_file.size > 5 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="File size must be less than 5MB")
        
        # Generate unique filename
        file_extension = cv_file.filename.split('.')[-1] if '.' in cv_file.filename else 'pdf'
        unique_filename = f"{uuid.uuid4()}.{file_extension}"
        
        # Create username from email (you can modify this logic as needed)
        username = email.split('@')[0]
        
        # Create user-specific directory
        user_upload_dir = UPLOAD_DIR / username
        user_upload_dir.mkdir(parents=True, exist_ok=True)
        
        # Save file
        file_path = user_upload_dir / unique_filename
        with open(file_path, "wb") as buffer:
            content = await cv_file.read()
            buffer.write(content)
        
        # Generate full URL for the CV
        cv_url = generate_cv_url(username, unique_filename)
    
    # Create application
    db_application = Application(
        job_id=job_id,
        first_name=first_name,
        middle_name=middle_name,
        last_name=last_name,
        dob=dob_datetime,
        state_of_origin=state_of_origin,
        address=address,
        email=email,
        phone=phone,
        portfolio=portfolio,
        social_link=social_link,
        experience=experience,
        cover_letter=cover_letter,
        cv_filename=cv_url  # Store the full URL instead of just filename
    )
    
    db.add(db_application)
    db.commit()
    db.refresh(db_application)
    
    return db_application

# Alternative: Add the route that matches your React form exactly
@app.post("/jobs/{job_id}/apply", response_model=ApplicationResponse)
async def apply_for_job(
    job_id: int,
    first_name: str = Form(...),
    middle_name: Optional[str] = Form(None),
    last_name: str = Form(...),
    dob: str = Form(...),
    state_of_origin: str = Form(...),
    address: str = Form(...),
    email: str = Form(...),
    phone: str = Form(...),
    portfolio: Optional[str] = Form(None),
    social_link: str = Form(...),
    experience: str = Form(...),
    cover_letter: str = Form(...),
    cv_file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db)
):
    """Submit a job application - Alternative endpoint that matches React form"""
    
    # Verify job exists and is active
    job = db.query(Job).filter(Job.id == job_id, Job.is_active == True).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found or no longer active")
    
    # Check if user already applied for this job
    existing_application = db.query(Application).filter(
        Application.job_id == job_id,
        Application.email == email
    ).first()
    
    if existing_application:
        raise HTTPException(
            status_code=400, 
            detail="You have already applied for this position"
        )
    
    # Convert date string to datetime
    try:
        dob_datetime = datetime.strptime(dob, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")
    
    cv_url = None
    if cv_file:
        # Validate file type and size
        allowed_types = ['application/pdf', 'application/msword', 
                        'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
        if cv_file.content_type not in allowed_types:
            raise HTTPException(
                status_code=400, 
                detail="Only PDF, DOC, and DOCX files are allowed"
            )
        
        # Check file size (5MB limit)
        if cv_file.size > 5 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="File size must be less than 5MB")
        
        # Generate unique filename
        file_extension = cv_file.filename.split('.')[-1] if '.' in cv_file.filename else 'pdf'
        unique_filename = f"{uuid.uuid4()}.{file_extension}"
        
        # Create username from email (you can modify this logic as needed)
        username = email.split('@')[0]
        
        # Create user-specific directory
        user_upload_dir = UPLOAD_DIR / username
        user_upload_dir.mkdir(parents=True, exist_ok=True)
        
        # Save file
        file_path = user_upload_dir / unique_filename
        with open(file_path, "wb") as buffer:
            content = await cv_file.read()
            buffer.write(content)
        
        # Generate full URL for the CV
        cv_url = generate_cv_url(username, unique_filename)
    
    # Create application
    db_application = Application(
        job_id=job_id,
        first_name=first_name,
        middle_name=middle_name,
        last_name=last_name,
        dob=dob_datetime,
        state_of_origin=state_of_origin,
        address=address,
        email=email,
        phone=phone,
        portfolio=portfolio,
        social_link=social_link,
        experience=experience,
        cover_letter=cover_letter,
        cv_filename=cv_url  # Store the full URL instead of just filename
    )
    
    db.add(db_application)
    db.commit()
    db.refresh(db_application)
    
    return db_application



@app.get("/applications/{application_id}", response_model=ApplicationWithJob)
def get_application(application_id: int, db: Session = Depends(get_db)):
    """Get a specific application (Admin only)"""
    application = db.query(Application).filter(Application.id == application_id).first()
    if application is None:
        raise HTTPException(status_code=404, detail="Application not found")
    return application




# Update your endpoint to use the model
@app.put("/applications/{application_id}/status")
def update_application_status(
    application_id: int,
    status_update: StatusUpdate,  # Use the Pydantic model
    db: Session = Depends(get_db)
):
    """Update application status (Admin only)"""
    valid_statuses = ["pending", "reviewed", "interviewed", "hired", "rejected", "accepted"]
    if status_update.status not in valid_statuses:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
        )
    
    application = db.query(Application).filter(Application.id == application_id).first()
    if application is None:
        raise HTTPException(status_code=404, detail="Application not found")
    
    application.status = status_update.status
    db.commit()
    
    return {"message": f"Application status updated to {status_update.status}"}


@app.get("/{username}/cv/{filename}")
async def get_cv_file(username: str, filename: str):
    """Serve CV files"""
    file_path = UPLOAD_DIR / username / filename
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="CV file not found")
    
    from fastapi.responses import FileResponse
    
    # Determine the correct media type based on file extension
    file_extension = filename.split('.')[-1].lower()
    media_type_map = {
        'pdf': 'application/pdf',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'png': 'image/png',
        'gif': 'image/gif'
    }
    
    media_type = media_type_map.get(file_extension, 'application/octet-stream')
    
    return FileResponse(
        path=file_path,
        media_type=media_type,
        filename=filename,
        headers={
            "Cache-Control": "no-cache",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET",
            "Access-Control-Allow-Headers": "*"
        }
    )

# Alternative: Add a specific endpoint for downloading CVs with proper headers
@app.get("/applications/{application_id}/download-cv")
async def download_application_cv(
    application_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Download CV for a specific application (Admin only)"""
    application = db.query(Application).filter(Application.id == application_id).first()
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
    
    if not application.cv_filename:
        raise HTTPException(status_code=404, detail="No CV file found for this application")
    
    # Extract filename from URL if it's stored as full URL
    if application.cv_filename.startswith('http'):
        # Extract the actual filename from the URL
        filename = application.cv_filename.split('/')[-1]
        username = application.email.split('@')[0]
    else:
        filename = application.cv_filename
        username = application.email.split('@')[0]
    
    file_path = UPLOAD_DIR / username / filename
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="CV file not found on server")
    
    # Determine the correct media type
    file_extension = filename.split('.')[-1].lower()
    media_type_map = {
        'pdf': 'application/pdf',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'png': 'image/png',
        'gif': 'image/gif'
    }
    
    media_type = media_type_map.get(file_extension, 'application/octet-stream')
    
    return FileResponse(
        path=file_path,
        media_type=media_type,
        filename=f"{application.first_name}_{application.last_name}_CV.{file_extension}",
        headers={
            "Content-Disposition": f"attachment; filename={application.first_name}_{application.last_name}_CV.{file_extension}",
            "Cache-Control": "no-cache"
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)