import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context


engine = create_engine('sqlite:///categories.db', echo=True)
Base = declarative_base(bind=engine)


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    password_hash = Column(String(64))
    data = relationship('Categories', backref='categories', lazy=True)
    items = relationship('Items', backref='items', lazy=True)


class Categories(Base):
    __tablename__ = 'categories'
    category_id = Column(Integer, primary_key=True)
    category_name = Column(String(50), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)


class Items(Base):
    __tablename__ = 'items'
    id = Column(Integer, primary_key=True)
    name = Column(String(20), nullable=False)
    user_id = (Column(Integer, ForeignKey('user.id'), nullable=False))
    cat_id = Column(Integer, ForeignKey('categories.category_id'))


def hash_password(self, password):
    self.password_hash = pwd_context.encrypt(password)


def verify_password(self, password):
    return pwd_context.verify(password, self.password_hash)


Base.metadata.create_all(engine)
