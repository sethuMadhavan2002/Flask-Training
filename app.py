from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from dotenv import load_dotenv
from dbModel import db, User, Login
from redis import StrictRedis
import jwt, os, json

load_dotenv()


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

db.init_app(app)

redis = StrictRedis(host="localhost", port=6379, db=0, decode_responses=True)

CACHE_EXPIRATION_TIME = 60

# def serialize_user(user):


# @app.before_request
# def before_request():
#     if request.endpoint in ["signup", "login", "clear-cache"]:
#         return

#     token = request.headers.get("auth_token")

#     if token == None:
#         return jsonify({"error": "Missing Authorization header"}), 401

#     if not token:
#         return jsonify({"error": "Invalid token"}), 401

#     try:
#         payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms="HS256")
#         request.user = payload
#         # print(payload)
#         # {
#         #     "access_token": "",
#         #     "refresh_token": "",
#         #     "user_email": "",
#         #     "details related to user": "",
#         # }

#         # check token expiry time
#         # user exists or not
#         # check the token has been logged out or not

#     except jwt.ExpiredSignatureError:
#         return jsonify({"error": "Token has expired"}), 401
#     except jwt.InvalidTokenError:
#         return jsonify({"error": "Invalid tokensss"}), 401


@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    name = data.get("name")
    email = data.get("email")
    mobile = data.get("mobile_no")
    password = data.get("password")
    user = User.query.filter(User.email == email, User.mobile_no == mobile).first()
    # user = db.session.query(db.exists().where(User.email == email)).scalar()
    if user:
        return jsonify({"error": "User already exist"}), 400

    hashed_password = generate_password_hash(password, method="sha256")
    newUser = User(name=name, email=email, mobile_no=mobile, password=hashed_password)
    db.session.add(newUser)
    db.session.commit()

    user_id = User.query.filter_by(email=email).first().id
    login_time = datetime.utcnow()
    logout_time = None
    newLogin = Login(user_id=user_id, login_time=login_time, logout_time=logout_time)
    db.session.add(newLogin)
    db.session.commit()

    payload = {"email": email, "name": name, "mobile": mobile, "password": password}

    headers = {"alg": "HS256", "typ": "JWT"}

    token = jwt.encode(
        app.config["SECRET_KEY"], algorithm="HS256", payload=payload, headers=headers
    )

    return (
        jsonify(
            {"token": jwt.decode(token, app.config["SECRET_KEY"], algorithms="HS256")}
        ),
        201,
    )


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    users = User.query.all()

    user = next((user for user in users if user.email == email), None)

    if user and check_password_hash(user.password, password):
        user_id = User.query.filter_by(email=email).first().id
        login_time = datetime.utcnow()
        logout_time = None

        # validation will be over
        # create login hst with required info
        # create a token with these payload {
        # Login id from Login,
        # User id from user table,
        # Token Created at
        # access or refresh token flag : true or flase it depends
        # }

        # {
        #     "access_token": "",
        #     "refresh_token": "",
        #     "user_email": "",
        #     "details related to user": "",
        # }

        newLogin = Login(
            user_id=user_id, login_time=login_time, logout_time=logout_time
        )
        db.session.add(newLogin)
        db.session.commit()

        login_id = (
            Login.query.filter(user_id == user_id, login_time == login_time).first().id
        )
        login_tm = (
            Login.query.filter(user_id == user_id, login_time == login_time)
            .first()
            .login_time
        )
        print("Login Time : ", login_time)
        print("new login time : ", login_tm)

        payload = {
            "login_id": login_id,
            "user_id": user_id,
            "login_time": str(login_time),
            "access_token": 1,
        }
        headers = {"alg": "HS256", "typ": "JWT"}

        token = jwt.encode(
            payload=payload,
            key=app.config["SECRET_KEY"],
            algorithm="HS256",
            headers=headers,
        )

        print(token)

        return (
            jsonify(
                {
                    "token": jwt.decode(
                        token,
                        key=app.config["SECRET_KEY"],
                        algorithms="HS256",
                        headers=headers,
                    )
                }
            ),
            200,
        )
    return jsonify({"error": "Invalid email or password"}), 401


@app.route("/logout")
def logout():
    user = getattr(request, "user", None)
    # print(user)
    if user:
        login_hst = Login.query.filter_by(id=user["login_id"]).first()
        if login_hst.logout_time == None:
            login_hst.logout_time = datetime.utcnow()
            db.session.commit()

        return jsonify({"message": "User logged out successfully"}), 200


@app.route("/profile", methods=["GET"])
def profile():
    user = getattr(request, "user", None)
    # print(user)
    if user:
        return (
            jsonify(
                {
                    "email": user["user_id"],
                    "message": "User profile",
                }
            ),
            200,
        )

    return jsonify({"error": "Unauthorized"}, 401)


@app.route("/user/<user_id>", methods=["GET"])
def get_user(user_id):
    cache_key = f"user:{user_id}"
    cached_data = redis.get(cache_key)
    print("CACHED DATA :", cached_data)

    if cached_data:
        return (
            jsonify(
                {"massage": "Data fetch from cache", "data": json.loads(cached_data)}
            ),
            200,
        )
    # print(1234567890)
    user_data = User.query.filter_by(id=user_id).first()
    # user_data = 1
    # print(user_data)

    if user_data:
        user_data_json = user_data.__json__()
        redis.setex(cache_key, CACHE_EXPIRATION_TIME, json.dumps(user_data_json))
        return (
            jsonify({"message": "Data fetched from db", "data": user_data_json}),
            200,
        )
    else:
        return jsonify({"error": "User not found"}), 404


@app.route("/clear-cache", methods=["DELETE"])
def clear_cache():
    redis.flushdb()
    return jsonify({"message": "Cache cleared"}), 200


@app.route("/create", methods=["POST"])
def create_user():
    data = request.json
    new_user = User(username=data["username"], email=data["email"])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created successfully"}), 201


@app.route("/read/<username>", methods=["GET"])
def read_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({"username": user.username, "email": user.email})
    return jsonify({"message": "User not found"}), 404


@app.route("/update/<username>", methods=["PUT"])
def update_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        data = request.json
        user.email = data["email"]
        db.session.commit()
        return jsonify({"message": "User updated successfully"})
    return jsonify({"message": "User not found"}), 404


@app.route("/delete/<username>", methods=["DELETE"])
def delete_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"})
    return jsonify({"message": "User not found"}), 404


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
