import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from app.models.attack_surface_models import Base

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)
Base.metadata.create_all(bind=engine)
print("Database tables created")
