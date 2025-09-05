from sqlmodel import SQLModel, create_engine, Session
from app.core.config import settings


engine = create_engine(settings.URL_DATABASE)

def create_db_and_tables():
    """
    Create the database and tables if they do not exist.
    """
    SQLModel.metadata.create_all(engine)

def get_session():
    """
    Data Bases Sessions generate that it's using like dependency.
    It sures that the session always will close.
    """
    with Session(engine) as session:
        yield session