from catalog_app.models import User, Categories, Items
from catalog_app.models import session

category = Categories(category_id=1, category_name='Snowboarding', user_id=1)
session.add(category)
session.commit()

category = Categories(category_id=2, category_name='Skiying', user_id=1)
session.add(category)
session.commit()

category = Categories(category_id=3, category_name='Surfing', user_id=1)
session.add(category)
session.commit()

item = Items(id=1, description="These specialized boots will "
                               "connect you to your board through "
                               "the bindings. You can "
                               "also rent these at"
                               " the resort, but it is "
                               "not recommended. "
                               "Snowboard boots are "
                               "designed to conform to your feet specifically,"
                               " so owning your own pair will be far "
                               "more comfortable. "
                               "Snowboard boots come in regular shoe sizes, "
                               "but sizing can vary "
                               "among different companies."
                               " Your boots should be snug, "
                               "but not tight to the point of "
                               "restriction.",
             name="Boots", user_id=1, cat_id=1)
session.add(item)
session.commit()

item = Items(id=2, name="Helmet",
             description="Your brain is the most "
                         "important organ in your body,"
                         " so wearing a helmet should be an easy "
                         "decision. As a beginner, you may struggle "
                         "with control, so protecting your head is "
                         "paramount. If you do not own a helmet, "
                         "the resort will have various options to"
                         " rent one "
                         "that ensure you will find one that fits.",
             user_id=1, cat_id=1)
session.add(item)
session.commit()

item = Items(id=3, name="Base and Mid Layers",
             description="Base and mid layers are "
                         "worn underneath your jacket and "
                         "pants. On particularly cold days, "
                         "proper base layering is crucial to"
                         " staying warm. You want to avoid "
                         "cotton products because "
                         "they are neither breathable nor"
                         " waterproof. Synthetic materials or "
                         "wool are effective with "
                         "wicking moisture and maintaining a"
                         " comfortable body temperature.",
             user_id=1, cat_id=1)
session.add(item)
session.commit()

# category = session.query(Categories).filter_by(user_id=1).all()
# for categories in category:
#     print(categories.category_name)

# item = Items(id=3, name="Ski Stick", user_id=1, cat_id=3)
# session.add(item)
# session.commit()

# item = Items(id=2, name="Stick", user_id=1, cat_id=3)
# session.add(item)
# session.commit()

# item = Items(id=4, name="Shoes", user_id=1, cat_id=3)
# session.add(item)
# session.commit()
