import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from flask_bcrypt import Bcrypt


engine = create_engine('sqlite:///categories.db', echo=True)
Base = declarative_base(bind=engine)
bcrypt = Bcrypt()


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(32), index=True)
    email =Column(String(100))
    username =Column(String(100))
    password = Column(String(64))
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


Base.metadata.create_all(engine)
