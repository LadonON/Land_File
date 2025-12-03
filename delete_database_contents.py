from app import app, db
from app import User

with app.app_context():
    num = db.session.query(User).delete()
    db.session.commit()
    print(f'Deleted {num} users from the user database')
