from flask import Flask, request, url_for, redirect, jsonify
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from json import JSONEncoder
from mongodbModel import Users, db, db_replica

load_dotenv()

app = Flask(__name__)

app.config["MONGODB_SETTINGS"] = {
    "db": "flask_training",
    "host": "mongodb://localhost:27017/flask_training",
}
app.json_encoder = JSONEncoder

db.init_app(app)


@app.route("/add", methods=["POST"])
def add():
    try:
        data = request.json
        hashed_password = generate_password_hash(data["password"])
        newUser = Users(
            name=data["name"], email=data["email"], password=hashed_password
        )
        newUser.save()
        return jsonify({"message": "User added successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/update/<email>", methods=["PUT"])
def update(email):
    try:
        data = request.json
        user = Users.objects.get(email=email)
        user.name = data.get("name", user.name)
        print(user.password)
        if data.get("password", None):
            new_hashed_password = generate_password_hash(data.password)
            user.password = new_hashed_password
        user.updated_time = datetime.utcnow

        user.save()

        return jsonify({"message": "User updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/getall", methods=["GET"])
def getall():
    try:
        users = Users.objects.all()
        user_list = [{"name": user.name, "email": user.email} for user in users]
        return jsonify({"users": user_list}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/get-by-id/<email>", methods=["GET"])
def getByID(email):
    try:
        user = Users.objects.get(email=email)
        return jsonify({"name": user.name, "email": user.email}), 200
    except Users.DoesNotExist:
        return jsonify({"error": "User Not Found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/delete/<email>", methods=["DELETE"])
def delete(email):
    try:
        user = Users.objects.get(email=email)
        print("User:", user)
        user.delete()
        return jsonify({"message": "User deleted successfully"}), 200
    except Users.DoesNotExist:
        return jsonify({"error": "User Not Found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
