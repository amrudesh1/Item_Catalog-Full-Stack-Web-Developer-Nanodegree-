import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from catalog_app import login_manager
from flask_login import UserMixin
from sqlalchemy.pool import StaticPool

engine = create_engine('sqlite:///categories.db', connect_args={'check_same_thread': False},
                       poolclass=StaticPool, echo=True)
Base = declarative_base(bind=engine)
DBSession = sessionmaker(bind=engine)
session = DBSession()


@login_manager.user_loader
def get_user(user_id):
    return session.query(User).get(int(user_id))


class User(Base, UserMixin):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(32), index=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(64))
    data = relationship('Categories', backref='categories', lazy=True)
    items = relationship('Items', backref='items', lazy=True)


def __repr__(self):
    return f"User('{self.name}', '{self.email}')"


class Categories(Base):
    __tablename__ = 'categories'
    category_id = Column(Integer, primary_key=True)
    category_name = Column(String(50), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)


class Items(Base):
    __tablename__ = 'items'
    id = Column(Integer, primary_key=True)
    name = Column(String(20), nullable=False)
    description = Column(String(200),nullable=True)
    user_id = (Column(Integer, ForeignKey('user.id')))
    cat_id = Column(Integer, ForeignKey('categories.category_id'))


Base.metadata.create_all(engine)
