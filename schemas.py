"""
Database Schemas for CodeSync DSA Tracker

Each Pydantic model represents a collection in MongoDB. The collection name is the lowercase of the class name.
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Dict, List
from datetime import datetime

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="BCrypt password hash")
    streak: int = Field(0, ge=0, description="Current daily streak in days")
    total_solved: int = Field(0, ge=0, description="Total problems solved")
    last_active_date: Optional[str] = Field(None, description="YYYY-MM-DD of last activity for streak calc")
    last_commit_at: Optional[datetime] = Field(None, description="Timestamp of last commit to GitHub")
    topics: Dict[str, int] = Field(default_factory=dict, description="Topic progress counts: arrays, dp, graphs, etc.")
    github_username: Optional[str] = None
    github_repo: Optional[str] = None

class Submission(BaseModel):
    user_id: str = Field(..., description="User id (stringified ObjectId)")
    problem_name: str
    topic: str
    difficulty: str
    date: str = Field(..., description="YYYY-MM-DD")
    notes: Optional[str] = None
    code: Optional[str] = None
    repo_path: Optional[str] = Field(None, description="Path in repo where file is committed")
    committed: bool = Field(False, description="Whether it was pushed to GitHub")
    commit_sha: Optional[str] = None
