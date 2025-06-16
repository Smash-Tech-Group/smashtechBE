from fastapi import FastAPI, HTTPException, Depends, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime
import json
import os
from pathlib import Path


# Pydantic models
class JobCreate(BaseModel):
    title: str
    location: str
    salary: str
    job_type: str 
    description: str
    requirements: str

class JobResponse(BaseModel):
    id: int
    title: str
    location: str
    salary: str
    job_type: str 
    description: str
    requirements: str
    created_at: datetime

class ApplicationCreate(BaseModel):
    job_id: int
    name: str
    email: EmailStr
    phone: str
    experience: str
    cover_letter: str

class ApplicationResponse(BaseModel):
    id: int
    job_id: int
    name: str
    email: str
    phone: str
    experience: str
    cover_letter: str
    resume_url: Optional[str] = None
    applied_at: datetime