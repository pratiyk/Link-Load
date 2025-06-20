from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import your API route modules - adjust import paths if needed
from app.api import link_scanner, threat_scanner, vulnerability_scanner, remediation

app = FastAPI(title="Link & Load API")

# Allow React frontend origin for cross-origin requests
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

# Include your routers with "/api" prefix
app.include_router(link_scanner.router, prefix="/api")
app.include_router(threat_scanner.router, prefix="/api")
app.include_router(vulnerability_scanner.router, prefix="/api")
app.include_router(remediation.router, prefix="/api")

@app.get("/")
async def root():
    return {"message": "Link & Load API is running"}
