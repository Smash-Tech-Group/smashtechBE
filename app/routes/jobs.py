from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta
import json
import os
import jwt
import bcrypt
from pathlib import Path
from enum import Enum

app = FastAPI(title="Job Management API")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # React dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT Configuration
SECRET_KEY = "your-secret-key-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Security
security = HTTPBearer()

# Create data directory
os.makedirs("data", exist_ok=True)

# Enums for better data consistency
class JobType(str, Enum):
    FULL_TIME = "Full-Time"
    PART_TIME = "Part-Time"
    CONTRACT = "Contract"
    INTERNSHIP = "Internship"
    REMOTE = "Remote"
    HYBRID = "Hybrid"

class ExperienceLevel(str, Enum):
    ENTRY = "Entry Level"
    JUNIOR = "Junior"
    MID = "Mid Level"
    SENIOR = "Senior"
    LEAD = "Lead"
    EXECUTIVE = "Executive"

class JobCategory(str, Enum):
    TECHNOLOGY = "Technology"
    MARKETING = "Marketing"
    SALES = "Sales"
    FINANCE = "Finance"
    HR = "Human Resources"
    OPERATIONS = "Operations"
    DESIGN = "Design"
    CUSTOMER_SERVICE = "Customer Service"
    ADMINISTRATION = "Administration"
    OTHER = "Other"

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

class JobCreate(BaseModel):
    title: str
    description: str
    requirements: str
    location: str = "Abuja"
    job_type: JobType = JobType.FULL_TIME
    category: JobCategory = JobCategory.OTHER
    experience_level: ExperienceLevel = ExperienceLevel.MID
    salary_min: Optional[int] = None
    salary_max: Optional[int] = None
    salary_currency: str = "NGN"
    benefits: Optional[str] = None
    application_deadline: Optional[str] = None
    company_name: str = "Company"
    company_description: Optional[str] = None
    is_remote_friendly: bool = False
    skills_required: Optional[str] = None  # Comma-separated skills
    employment_status: str = "Active"

class JobResponse(BaseModel):
    id: int
    title: str
    description: str
    requirements: str
    location: str
    job_type: str
    category: str
    experience_level: str
    salary_min: Optional[int]
    salary_max: Optional[int]
    salary_currency: str
    benefits: Optional[str]
    application_deadline: Optional[str]
    company_name: str
    company_description: Optional[str]
    is_remote_friendly: bool
    skills_required: Optional[str]
    employment_status: str
    created_at: str

class ApplicationCreate(BaseModel):
    job_id: int
    name: str
    email: EmailStr
    phone: str
    experience: str
    cover_letter: str
    resume_url: Optional[str] = None
    portfolio_url: Optional[str] = None
    linkedin_url: Optional[str] = None

class ApplicationResponse(BaseModel):
    id: int
    job_id: int
    name: str
    email: str
    phone: str
    experience: str
    cover_letter: str
    resume_url: Optional[str]
    portfolio_url: Optional[str]
    linkedin_url: Optional[str]
    applied_at: str

# Data storage functions
def load_users():
    try:
        with open("data/users.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_users(users):
    with open("data/users.json", "w") as f:
        json.dump(users, f, indent=2)

def load_jobs():
    try:
        with open("data/jobs.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_jobs(jobs):
    with open("data/jobs.json", "w") as f:
        json.dump(jobs, f, indent=2, default=str)

def load_applications():
    try:
        with open("data/applications.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_applications(applications):
    with open("data/applications.json", "w") as f:
        json.dump(applications, f, indent=2, default=str)

def get_next_id(items):
    if not items:
        return 1
    return max(item["id"] for item in items) + 1

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

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Auth endpoints
@app.post("/register", response_model=dict)
async def register(user: UserCreate):
    users = load_users()
    
    # Check if user exists
    if any(u["username"] == user.username or u["email"] == user.email for u in users):
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    # Create new user
    new_user = {
        "id": get_next_id(users),
        "username": user.username,
        "email": user.email,
        "password": hash_password(user.password),
        "created_at": datetime.now().isoformat()
    }
    
    users.append(new_user)
    save_users(users)
    
    return {"message": "User created successfully"}

@app.post("/login", response_model=Token)
async def login(user: UserLogin):
    users = load_users()
    
    # Find user
    user_data = next((u for u in users if u["username"] == user.username), None)
    if not user_data or not verify_password(user.password, user_data["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create token
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# Job endpoints
@app.get("/")
async def root():
    return {"message": "Job Management API is running"}

@app.get("/jobs", response_model=List[JobResponse])
async def get_jobs():
    jobs = load_jobs()
    return jobs

@app.get("/jobs/{job_id}", response_model=JobResponse)
async def get_job(job_id: int):
    jobs = load_jobs()
    job = next((job for job in jobs if job["id"] == job_id), None)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job

@app.post("/jobs", response_model=JobResponse)
async def create_job(job: JobCreate, current_user: str = Depends(get_current_user)):
    jobs = load_jobs()
    new_job = {
        "id": get_next_id(jobs),
        "title": job.title,
        "description": job.description,
        "requirements": job.requirements,
        "location": job.location,
        "job_type": job.job_type.value,
        "category": job.category.value,
        "experience_level": job.experience_level.value,
        "salary_min": job.salary_min,
        "salary_max": job.salary_max,
        "salary_currency": job.salary_currency,
        "benefits": job.benefits,
        "application_deadline": job.application_deadline,
        "company_name": job.company_name,
        "company_description": job.company_description,
        "is_remote_friendly": job.is_remote_friendly,
        "skills_required": job.skills_required,
        "employment_status": job.employment_status,
        "created_at": datetime.now().isoformat()
    }
    jobs.append(new_job)
    save_jobs(jobs)
    return new_job

@app.put("/jobs/{job_id}", response_model=JobResponse)
async def update_job(job_id: int, job: JobCreate, current_user: str = Depends(get_current_user)):
    jobs = load_jobs()
    job_index = next((i for i, j in enumerate(jobs) if j["id"] == job_id), None)
    if job_index is None:
        raise HTTPException(status_code=404, detail="Job not found")
    
    jobs[job_index].update({
        "title": job.title,
        "description": job.description,
        "requirements": job.requirements,
        "location": job.location,
        "job_type": job.job_type.value,
        "category": job.category.value,
        "experience_level": job.experience_level.value,
        "salary_min": job.salary_min,
        "salary_max": job.salary_max,
        "salary_currency": job.salary_currency,
        "benefits": job.benefits,
        "application_deadline": job.application_deadline,
        "company_name": job.company_name,
        "company_description": job.company_description,
        "is_remote_friendly": job.is_remote_friendly,
        "skills_required": job.skills_required,
        "employment_status": job.employment_status
    })
    save_jobs(jobs)
    return jobs[job_index]

@app.delete("/jobs/{job_id}")
async def delete_job(job_id: int, current_user: str = Depends(get_current_user)):
    jobs = load_jobs()
    applications = load_applications()
    
    job_index = next((i for i, j in enumerate(jobs) if j["id"] == job_id), None)
    if job_index is None:
        raise HTTPException(status_code=404, detail="Job not found")
    
    removed_job = jobs.pop(job_index)
    save_jobs(jobs)
    
    # Remove related applications
    applications = [app for app in applications if app["job_id"] != job_id]
    save_applications(applications)
    
    return {"message": f"Job '{removed_job['title']}' deleted"}

# Application endpoints
@app.get("/applications", response_model=List[ApplicationResponse])
async def get_applications(current_user: str = Depends(get_current_user)):
    applications = load_applications()
    return applications

@app.get("/jobs/{job_id}/applications", response_model=List[ApplicationResponse])
async def get_job_applications(job_id: int, current_user: str = Depends(get_current_user)):
    applications = load_applications()
    job_applications = [app for app in applications if app["job_id"] == job_id]
    return job_applications

@app.post("/applications", response_model=ApplicationResponse)
async def create_application(application: ApplicationCreate):
    # Verify job exists
    jobs = load_jobs()
    job = next((job for job in jobs if job["id"] == application.job_id), None)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    applications = load_applications()
    new_application = {
        "id": get_next_id(applications),
        "job_id": application.job_id,
        "name": application.name,
        "email": application.email,
        "phone": application.phone,
        "experience": application.experience,
        "cover_letter": application.cover_letter,
        "resume_url": application.resume_url,
        "portfolio_url": application.portfolio_url,
        "linkedin_url": application.linkedin_url,
        "applied_at": datetime.now().isoformat()
    }
    applications.append(new_application)
    save_applications(applications)
    return new_application

# Utility endpoints
@app.get("/job-types")
async def get_job_types():
    return [{"value": job_type.value, "label": job_type.value} for job_type in JobType]

@app.get("/categories")
async def get_categories():
    return [{"value": category.value, "label": category.value} for category in JobCategory]

@app.get("/experience-levels")
async def get_experience_levels():
    return [{"value": level.value, "label": level.value} for level in ExperienceLevel]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)