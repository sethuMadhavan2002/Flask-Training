from flask import Flask
from flask_mongoengine import MongoEngine
from datetime import datetime

app = Flask(__name__)


db = MongoEngine()


class Users(db.Document):
    meta = {
        "collection": "user_details",
    }
    id = db.SequenceField(primary_key=True)
    name = db.StringField(required=True)
    email = db.EmailField(required=True, unique=True)
    password = db.StringField(required=True, unique=True)
    created_time = db.DateTimeField(default=datetime.utcnow)
    updated_time = db.DateTimeField(default=datetime.utcnow)
