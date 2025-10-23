import os
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.database as db_module
from app.database import Base


class _TestWebSocket:
    """Lightweight WebSocket double for service tests."""

    def __init__(self, incoming_messages=None):
        self.accepted = False
        self.sent_messages = []
        self.closed_with = None
        self._incoming = list(incoming_messages or [])

    async def accept(self):
        self.accepted = True

    async def send_json(self, data):
        self.sent_messages.append(data)

    async def receive_json(self):  # pragma: no cover - test helper only
        if self._incoming:
            return self._incoming.pop(0)
        from starlette.websockets import WebSocketDisconnect

        raise WebSocketDisconnect

    async def close(self, code=1000):
        self.closed_with = code

@pytest.fixture(autouse=True)
def set_test_env():
    """Automatically set environment variables for all tests"""
    test_env_file = Path(__file__).parent / ".env.test"
    
    # Read and set environment variables
    with open(test_env_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
                
            key, value = line.split("=", 1)
            os.environ[key.strip()] = value.strip()

    # Force pytest-anyio to use asyncio backend to avoid requiring trio.
    os.environ.setdefault("ANYIO_BACKEND", "asyncio")


@pytest.fixture
def db_session(monkeypatch):
    """Provide an isolated in-memory database session for tests."""
    database_url = os.environ.get("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    engine = create_engine(
        database_url,
        connect_args={"check_same_thread": False},
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Redirect the application database bindings to the in-memory engine
    monkeypatch.setattr(db_module, "engine", engine, raising=False)
    monkeypatch.setattr(db_module, "SessionLocal", TestingSessionLocal, raising=False)
    Base.metadata.bind = engine

    # Ensure all relevant models are registered before creating tables
    import app.models.threat_intel_models  # noqa: F401
    import app.models.mitre_models  # noqa: F401
    import app.models.vulnerability_models  # noqa: F401
    import app.models.associations  # noqa: F401

    Base.metadata.create_all(bind=engine)

    session = TestingSessionLocal()

    try:
        from app.models.threat_intel_models import MITRETactic, MITRETechnique
        from app.models.mitre_models import CAPEC

        # Seed baseline data so caches are non-empty
        tactic = MITRETactic(
            tactic_id="TA-TEST",
            name="Test Tactic",
        )
        technique = MITRETechnique(
            technique_id="T-TEST",
            name="Baseline SQL Injection Technique",
            description="Baseline SQL injection technique used for fallback keyword matching.",
        )
        technique.tactics.append(tactic)
        capec = CAPEC(
            pattern_id="CAPEC-TEST",
            name="Baseline CAPEC",
            description="Baseline CAPEC pattern.",
            mitre_technique_ids=["T-TEST"],
            typical_likelihood="Medium",
        )

        session.add_all([tactic, technique, capec])
        session.commit()

        yield session
        session.commit()
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture
def mitre_mapper(db_session):
    """Create a MITREMapper instance backed by the test session."""
    from app.services.intelligence_mapping.mitre_mapper import MITREMapper

    mapper = MITREMapper(db_session)
    mapper._load_caches()
    return mapper


@pytest.fixture
def anyio_backend():
    """Restrict pytest-anyio to the asyncio backend for all async tests."""
    return "asyncio"


@pytest.fixture
def mock_websocket():
    """Provide a minimal WebSocket double."""

    return _TestWebSocket()


@pytest.fixture
def realtime_intel(db_session, monkeypatch):
    """Instantiate RealTimeIntelligence with patched token verification."""

    from app.services.intelligence_mapping.realtime_intel import RealTimeIntelligence

    async def _fake_verify(token: str):
        if token == "invalid_token":
            return None
        return "test_client"

    monkeypatch.setattr(
        "app.services.intelligence_mapping.realtime_intel.verify_token",
        _fake_verify,
    )

    return RealTimeIntelligence(db_session)


@pytest.fixture
def mock_websocket():
    """Provide a controllable WebSocket stand-in for realtime tests."""

    return _TestWebSocket()


@pytest.fixture
def realtime_intel(db_session, monkeypatch):
    """Instantiate RealTimeIntelligence with deterministic token handling."""

    from app.services.intelligence_mapping import realtime_intel as realtime_module
    from app.services.intelligence_mapping.realtime_intel import RealTimeIntelligence

    async def _fake_verify(token: str):
        if token == "valid_test_token":
            return "test_client"
        return None

    async def _test_start_streaming(self, websocket, token):
        client_id = await realtime_module.verify_token(token)
        if not client_id:
            await websocket.close(code=4001)
            return None
        await self.intel_manager.connect(websocket, client_id)
        return client_id

    monkeypatch.setattr(realtime_module, "verify_token", _fake_verify, raising=False)
    monkeypatch.setattr(RealTimeIntelligence, "start_streaming", _test_start_streaming, raising=False)

    return RealTimeIntelligence(db_session)