import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from typing import Optional
from fastapi import FastAPI, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(
    title="SIH Scholarship Offline-First Sync & Pre-Check API",
    version="1.1.1",
    description="Backend supporting user authentication, profile sync, and offline form synchronization."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILE = "sih_scholarship.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mobile TEXT UNIQUE NOT NULL,
            pin_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            user_id INTEGER PRIMARY KEY,
            full_name TEXT,
            age INTEGER,
            gender TEXT,
            state TEXT,
            district TEXT,
            tribal_sub_caste TEXT,
            course_level TEXT,
            annual_income REAL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS applications (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            applicant_name TEXT NOT NULL,
            annual_income REAL NOT NULL,
            category TEXT NOT NULL,
            aadhaar_hash TEXT NOT NULL,
            document_status TEXT DEFAULT 'Pending',
            sync_status TEXT DEFAULT 'Synced',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    conn.commit()
    conn.close()

init_db()

def hash_pin(pin: str) -> str:
    salt = secrets.token_hex(16)
    scrambled = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 200000).hex()
    return salt + "$" + scrambled

def pin_is_correct(pin: str, stored: str) -> bool:
    try:
        salt, scrambled = stored.split("$")
        test = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 200000).hex()
        return hmac.compare_digest(test, scrambled)
    except Exception:
        return False

SESSIONS = {}

class AuthPayload(BaseModel):
    mobile: str = Field(..., pattern=r"^\d{10}$")
    pin: str = Field(..., pattern=r"^\d{6}$")

class ApplicationPayload(BaseModel):
    id: str
    applicant_name: str
    annual_income: float
    category: str
    aadhaar_hash: str

class PreCheckRequest(BaseModel):
    applicant_name: str
    annual_income: float
    category: str
    income_certificate_text: Optional[str] = ""

@app.get("/api/mobile-exists/{mobile}")
def check_mobile(mobile: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE mobile = ?", (mobile,))
    exists = cursor.fetchone() is not None
    conn.close()
    return {"exists": exists}

@app.post("/api/register")
def register_user(payload: AuthPayload):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (mobile, pin_hash) VALUES (?, ?)", (payload.mobile, hash_pin(payload.pin)))
        conn.commit()
        user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail={"error": "exists"})
    conn.close()
    
    token = secrets.token_hex(24)
    SESSIONS[token] = user_id
    return {"token": token, "state": {"profile": None, "applications": [], "documents": {}, "notifications": []}}

@app.post("/api/login")
def login_user(payload: AuthPayload):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, pin_hash FROM users WHERE mobile = ?", (payload.mobile,))
    user = cursor.fetchone()
    conn.close()
    
    if not user or not pin_is_correct(payload.pin, user["pin_hash"]):
        raise HTTPException(status_code=401, detail={"error": "wrong_pin"})
    
    user_id = user["id"]
    token = secrets.token_hex(24)
    SESSIONS[token] = user_id
    
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM profiles WHERE user_id = ?", (user_id,))
    p = cursor.fetchone()
    
    profile = None
    if p:
        profile = {
            "name": p["full_name"], "age": p["age"], "gender": p["gender"],
            "state": p["state"], "district": p["district"], "subCaste": p["tribal_sub_caste"],
            "courseLevel": p["course_level"], "income": p["annual_income"]
        }
        
    cursor.execute("SELECT * FROM applications WHERE user_id = ?", (user_id,))
    apps = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return {
        "token": token,
        "state": {
            "profile": profile,
            "applications": apps,
            "documents": {},
            "notifications": []
        }
    }

@app.get("/api/me")
def get_me(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail={"error": "unauthorized"})
    token = authorization.split(" ")[1]
    user_id = SESSIONS.get(token)
    if not user_id:
        raise HTTPException(status_code=401, detail={"error": "unauthorized"})
        
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM profiles WHERE user_id = ?", (user_id,))
    p = cursor.fetchone()
    
    profile = None
    if p:
        profile = {
            "name": p["full_name"], "age": p["age"], "gender": p["gender"],
            "state": p["state"], "district": p["district"], "subCaste": p["tribal_sub_caste"],
            "courseLevel": p["course_level"], "income": p["annual_income"]
        }
    cursor.execute("SELECT * FROM applications WHERE user_id = ?", (user_id,))
    apps = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return {"state": {"profile": profile, "applications": apps}}

@app.put("/api/state")
def update_state(state_data: dict, authorization: Optional[str] = Header(None)):
    user_id = 1
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        user_id = SESSIONS.get(token, 1)
        
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    p = state_data.get("profile")
    if p:
        cursor.execute("""
            INSERT INTO profiles (user_id, full_name, age, gender, state, district, tribal_sub_caste, course_level, annual_income)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                full_name=excluded.full_name, age=excluded.age, gender=excluded.gender,
                state=excluded.state, district=excluded.district, tribal_sub_caste=excluded.tribal_sub_caste,
                course_level=excluded.course_level, annual_income=excluded.annual_income
        """, (user_id, p.get("name"), p.get("age"), p.get("gender"), p.get("state"), p.get("district"), p.get("subCaste"), p.get("courseLevel"), p.get("income")))
        conn.commit()
    conn.close()
    return {"ok": True}

@app.post("/api/v1/pre-check")
def run_ai_pre_check(data: PreCheckRequest):
    warnings = []
    is_eligible = True
    if data.category.upper() in ["SC", "ST", "PVTG"] and data.annual_income > 300000:
        warnings.append("Income is near or exceeds standard threshold for specific tribal sub-schemes.")
    elif data.annual_income > 600000:
        is_eligible = False
        warnings.append("Annual income exceeds general welfare scheme ceilings.")
    return {"status": "success", "is_eligible": is_eligible, "warnings": warnings}

@app.post("/api/v1/sync-application", status_code=status.HTTP_201_CREATED)
def sync_application(app_data: ApplicationPayload, authorization: Optional[str] = Header(None)):
    user_id = 1
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        user_id = SESSIONS.get(token, 1)

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO applications (id, user_id, applicant_name, annual_income, category, aadhaar_hash, sync_status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (app_data.id, user_id, app_data.applicant_name, app_data.annual_income, app_data.category.upper(), app_data.aadhaar_hash, "Synced"))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Payload synced successfully."}

@app.get("/api/v1/applications")
def get_applications():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM applications ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return {"applications": [dict(row) for row in rows]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
