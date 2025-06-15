from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Importing both API route modules
from app.api import link_scanner, threat_scanner

app = FastAPI()

# CORS settings: allow React dev server (localhost:3000) to access this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Update if you use Vite (usually 5173)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register both routers
app.include_router(link_scanner.router)
app.include_router(threat_scanner.router)

# Root test route
@app.get("/")
def read_root():
    return {"message": "Link & Load API is running"}
