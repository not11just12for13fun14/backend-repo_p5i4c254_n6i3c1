import os
from datetime import datetime, timezone, date
from typing import Optional, List, Dict

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import jwt

from database import db, create_document, get_documents
from schemas import User as UserSchema, Submission as SubmissionSchema

JWT_SECRET = os.getenv("JWT_SECRET", "devsecret")
JWT_ALG = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="CodeSync DSA Tracker API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------ Helpers ------------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_token(payload: dict) -> str:
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


class AuthResponse(BaseModel):
    token: str
    user: dict


class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    github_username: Optional[str] = None
    github_repo: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SubmissionRequest(BaseModel):
    problem_name: str
    topic: str
    difficulty: str
    date: str
    notes: Optional[str] = None
    code: Optional[str] = None


# ------------------ Auth Routes ------------------

@app.post("/api/auth/signup", response_model=AuthResponse)
def signup(req: SignupRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    existing = db.user.find_one({"email": req.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = UserSchema(
        name=req.name,
        email=req.email,
        password_hash=hash_password(req.password),
        github_username=req.github_username,
        github_repo=req.github_repo,
        topics={"arrays": 0, "dp": 0, "graphs": 0, "linked list": 0},
    )
    uid = create_document("user", user)
    payload = {"sub": uid, "email": user.email, "name": user.name}
    token = create_token(payload)
    u = db.user.find_one({"_id": db.user.find_one({"email": user.email})["_id"]})
    u["_id"] = str(u["_id"])  # stringify id
    return AuthResponse(token=token, user=u)


@app.post("/api/auth/login", response_model=AuthResponse)
def login(req: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    u = db.user.find_one({"email": req.email})
    if not u:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if not verify_password(req.password, u.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    payload = {"sub": str(u["_id"]), "email": u["email"], "name": u["name"]}
    token = create_token(payload)
    u["_id"] = str(u["_id"])  # stringify id
    return AuthResponse(token=token, user=u)


# ------------------ Dashboard Data ------------------

@app.get("/api/dashboard/{user_id}")
def get_dashboard(user_id: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    u = db.user.find_one({"_id": __import__("bson").ObjectId(user_id)})
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    submissions = list(db.submission.find({"user_id": user_id}))
    # compute streak and topic progress
    today = date.today().strftime("%Y-%m-%d")
    dates = sorted({s.get("date") for s in submissions if s.get("date")})
    streak = 0
    if dates:
        # work backwards from today
        d = date.fromisoformat(today)
        while d.strftime("%Y-%m-%d") in dates:
            streak += 1
            d = d.fromordinal(d.toordinal() - 1)
    topics: Dict[str, int] = {}
    for s in submissions:
        t = s.get("topic", "other").lower()
        topics[t] = topics.get(t, 0) + 1
    u["streak"] = streak
    u["topics"] = topics or u.get("topics", {})
    u["total_solved"] = len(submissions)
    u["_id"] = str(u["_id"])  # stringify id
    return {"user": u, "submissions": submissions}


# ------------------ GitHub Commit ------------------

class GitHubCommitResponse(BaseModel):
    committed: bool
    url: Optional[str] = None


def github_commit(repo: str, token: str, path: str, content: str, message: str) -> GitHubCommitResponse:
    import base64
    import requests

    api = f"https://api.github.com/repos/{repo}/contents/{path}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    data = {
        "message": message,
        "content": base64.b64encode(content.encode()).decode(),
    }
    r = requests.put(api, headers=headers, json=data)
    if r.status_code in (200, 201):
        return GitHubCommitResponse(committed=True, url=r.json().get("content", {}).get("html_url"))
    else:
        raise HTTPException(status_code=400, detail=f"GitHub commit failed: {r.text}")


@app.post("/api/upload/{user_id}")
def upload_and_commit(user_id: str, req: SubmissionRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    u = db.user.find_one({"_id": __import__("bson").ObjectId(user_id)})
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    # Save submission
    sub = SubmissionSchema(
        user_id=user_id,
        problem_name=req.problem_name,
        topic=req.topic,
        difficulty=req.difficulty,
        date=req.date,
        notes=req.notes,
        code=req.code,
    )
    sid = create_document("submission", sub)

    # Commit to GitHub if configured
    gh_repo = u.get("github_repo")
    gh_token = os.getenv("GITHUB_PAT")
    if gh_repo and gh_token and (req.notes or req.code):
        safe_name = req.problem_name.strip().replace(" ", "-")
        file_ext = "md" if req.notes and not req.code else "md"
        folder = req.topic.lower().replace(" ", "-")
        path = f"dsa/{folder}/{req.difficulty.lower()}-{safe_name}-{req.date}.{file_ext}"
        content = f"# {req.problem_name}\n\n- Topic: {req.topic}\n- Difficulty: {req.difficulty}\n- Date: {req.date}\n\n## Notes\n\n{req.notes or ''}\n\n## Code\n\n```\n{req.code or ''}\n```\n"
        res = github_commit(gh_repo, gh_token, path, content, f"chore: add {req.problem_name}")
        db.submission.update_one({"_id": __import__("bson").ObjectId(sid)}, {"$set": {"committed": True, "repo_path": path}})
        db.user.update_one({"_id": __import__("bson").ObjectId(user_id)}, {"$set": {"last_commit_at": datetime.now(timezone.utc)}})
        return {"ok": True, "committed": res.committed, "url": res.url}

    return {"ok": True, "committed": False}


# ------------------ Peer Comparison ------------------

@app.get("/api/peers")
def peers():
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    users = list(db.user.find({}, {"password_hash": 0}))
    for u in users:
        uid = str(u["_id"])
        subs = db.submission.count_documents({"user_id": uid})
        u["_id"] = uid
        u["total_solved"] = subs
    users.sort(key=lambda x: (-x.get("streak", 0), -x.get("total_solved", 0)))
    return {"users": users}


@app.get("/")
def root():
    return {"message": "CodeSync DSA Tracker API"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        from database import db as _db
        if _db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = _db.name if hasattr(_db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = _db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
