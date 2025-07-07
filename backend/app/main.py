from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import (
    link_scanner,
    threat_scanner,
    vulnerability_scanner,
    remediation,
    darkweb_scanner,
    phishing_detector
)

app = FastAPI(title="Link & Load API")

origins = [
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(link_scanner.router, prefix="/api")
app.include_router(threat_scanner.router, prefix="/api")
app.include_router(vulnerability_scanner.router, prefix="/api")
app.include_router(remediation.router, prefix="/api")
app.include_router(darkweb_scanner.router, prefix="/api")
app.include_router(phishing_detector.router, prefix="/api")

@app.get("/")
async def root():
    return {"message": "Link & Load API is running"}
