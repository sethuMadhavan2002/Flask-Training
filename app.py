from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://madhav:Madhav-2492@localhost/crud"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False)


# db.create_all()


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
