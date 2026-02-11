import os
import json
import firebase_admin
from firebase_admin import credentials, firestore
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ✅ CORRECT: load .env from backend/
load_dotenv(os.path.join(BASE_DIR, ".env"))

print("BASE_DIR:", BASE_DIR)

service_account_json_str = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON")
print("SERVICE_ACCOUNT_JSON length:", len(service_account_json_str or ""))

if not service_account_json_str:
    raise RuntimeError("FIREBASE_SERVICE_ACCOUNT_JSON is missing or empty")

if not firebase_admin._apps:
    service_account_info = json.loads(service_account_json_str)
    cred = credentials.Certificate(service_account_info)
    firebase_admin.initialize_app(cred)

db = firestore.client()
