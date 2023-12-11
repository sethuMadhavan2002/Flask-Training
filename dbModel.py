from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class Basemodel(db.Model):
    __abstract__ = True
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    updated_date = db.Column(db.DateTime, default=datetime.utcnow)


class User(Basemodel):
    __tablename__ = "user_details"
    # id = db.Column(
    #     db.Integer, db.Sequence("id", start=1000, increment=1), primary_key=True
    # )
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    mobile_no = db.Column(db.String(10), unique=True, nullable=False)
    password = db.Column(db.String(500), nullable=False)

    def __json__(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "mobile_no": self.mobile_no,
            "password": self.password,
        }


class Login(Basemodel):
    __tablename__ = "login_details"
    # id = db.Column(
    #     db.Integer, db.Sequence("id", start=1000, increment=1), primary_key=True
    # )
    user_id = db.Column(db.Integer, db.ForeignKey("user_details.id"))
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    logout_time = db.Column(db.DateTime)
