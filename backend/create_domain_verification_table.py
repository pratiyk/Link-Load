"""Utility script to create the domain_verifications table."""
from app.database import Base, engine
from app.models.domain_verification import DomainVerification


def main() -> None:
    Base.metadata.create_all(bind=engine, tables=[DomainVerification.__table__])
    print("Domain verification table is ready.")


if __name__ == "__main__":
    main()
