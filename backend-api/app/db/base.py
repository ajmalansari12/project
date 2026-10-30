"""Declarative base and shared metadata configuration for SQLAlchemy 2.x."""

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

# Standard naming convention for indexes and constraints
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata_obj = MetaData(naming_convention=NAMING_CONVENTION)


class Base(DeclarativeBase):
    """Shared declarative base for all Sentinel-EDR database models."""

    metadata = metadata_obj
