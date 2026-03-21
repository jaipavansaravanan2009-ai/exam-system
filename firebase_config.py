import os
import json
import base64
import firebase_admin
from firebase_admin import credentials, firestore
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# 1. Firebase Setup using a Service Account Key
# Usually, for server-side Python, we use the Service Account JSON.
# If you are using the Base64 method we set up for Render/Railway:
base64_key = os.getenv("FIREBASE_BASE64")

if base64_key:
    # Decode the Base64 string into a JSON dictionary
    decoded_key = json.loads(base64.b64decode(base64_key).decode('utf-8'))
    cred = credentials.Certificate(decoded_key)
else:
    # Fallback: If running locally with a physical file
    # cred = credentials.Certificate("path/to/serviceAccountKey.json")
    print("❌ Error: FIREBASE_BASE64 not found in environment variables")
    exit(1)

# 2. Initialize the App (only if not already initialized)
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)

# 3. Initialize Firestore
db = firestore.client()

# This is equivalent to 'module.exports = db'
# In other files, you just do: from firebase_config import db