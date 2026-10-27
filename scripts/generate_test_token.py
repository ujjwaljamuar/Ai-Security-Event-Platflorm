import os
import time

import jwt
from dotenv import load_dotenv

load_dotenv()

secret = os.environ["JWT_SECRET"]
now = int(time.time())

payload = {
    "sub": "analyst-001",
    "role": "admin",
    "iss": os.getenv(
        "JWT_ISSUER",
        "ai-security-event-platform",
    ),
    "aud": os.getenv("JWT_AUDIENCE", "security-event-api"),
    "iat": now,
    "exp": now + 3600,
}

token = jwt.encode(payload, secret, algorithm="HS256")
print(token)
