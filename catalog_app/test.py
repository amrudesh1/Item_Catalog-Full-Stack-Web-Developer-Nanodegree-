from models import User, Categories, Items, session

firstResult = session.query(User).all()
datas = session.query(User).all()

for data in datas:
    print(data.id)


