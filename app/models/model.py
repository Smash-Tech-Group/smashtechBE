from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}')>"

class Job(Base):
    __tablename__ = "jobs"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    requirements = Column(Text, nullable=True)
    location = Column(String(100), nullable=False, default="Abuja")
    
    # Job type and employment details
    job_type = Column(String(50), nullable=False, default="Full Time")
    
    # Salary information - keeping both for flexibility
    salary = Column(String(100), nullable=True)
    salary_range = Column(String(100), nullable=True) 
    
    # Application and status management
    application_deadline = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship to applications
    applications = relationship("Application", back_populates="job", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Job(id={self.id}, title='{self.title}', location='{self.location}', job_type='{self.job_type}')>"
    
    @property
    def application_count(self):
        """Get the number of applications for this job"""
        return len(self.applications)
    
    @property
    def salary_display(self):
        """Get the salary display string - prioritizes salary_range over salary"""
        return self.salary_range if self.salary_range else self.salary
    
    @property
    def is_application_open(self):
        """Check if applications are still open"""
        if not self.is_active:
            return False
        if self.application_deadline:
            return datetime.utcnow() <= self.application_deadline
        return True

class Application(Base):
    __tablename__ = "applications"
    
    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False)
    first_name = Column(String(100), nullable=False)
    middle_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=False)
    dob = Column(DateTime, default=datetime.utcnow)
    state_of_origin = Column(String(100), nullable=False)
    address = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False)
    phone = Column(String(20), nullable=False)
    portfolio = Column(String, nullable=True)
    social_link = Column(String(100), nullable=False)
    experience = Column(Text, nullable=False)
    cover_letter = Column(Text, nullable=False)
    cv_filename = Column(String(255), nullable=True) 
    applied_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(50), default="pending")
    
    # Relationship to job
    job = relationship("Job", back_populates="applications")
    
    def __repr__(self):
        return f"<Application(id={self.id}, name='{self.name}', job_id={self.job_id}, status='{self.status}')>"