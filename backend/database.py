from sqlmodel import SQLModel, create_engine, Session

DATABASE_URL = "sqlite:///alerts.db"
engine = create_engine(DATABASE_URL)


def init_db():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session
