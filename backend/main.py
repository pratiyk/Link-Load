from fastapi import FastAPI
from app.api import link_scanner
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Correct CORS settings to allow React (running on port 3000) to call the backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Corrected: React default port
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include your route
app.include_router(link_scanner.router)

# Optional test route
@app.get("/")
def read_root():
    return {"message": "Link & Load API is running"}
