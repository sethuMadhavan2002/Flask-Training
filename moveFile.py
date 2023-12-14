from flask import Flask, request, jsonify
import shutil, os

app = Flask(__name__)

app.config["UPLOAD_FOLDER"] = os.getenv("UPLOAD_FOLDER")

allowed_extensions = os.getenv("ALLOWED_EXTENSIONS")


def allowed_file(filename):
    # print(filename.rsplit(".", 1)[1].lower() in allowed_extensions, "." in filename)
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


@app.route("/move", methods=["POST"])
def move():
    if "file" not in request.files:
        return jsonify({"error": "file missing"}), 500

    file = request.files["file"]
    # print(file.filename)

    if file.filename == "":
        return jsonify({"error": "file name missing"}), 500

    if file and allowed_file(file.filename):
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

        file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(file_path)

        destination_folder = os.path.join(
            app.config["UPLOAD_FOLDER"], file.filename.rsplit(".", 1)[1].lower()
        )
        os.makedirs(destination_folder, exist_ok=True)

        shutil.move(file_path, os.path.join(destination_folder, file.filename))
        return (
            jsonify(
                {
                    "message": f"file uploaded and moved successfully to {destination_folder}"
                }
            ),
            200,
        )

    return jsonify({"error": "invalid file type"}), 200


if __name__ == "__main__":
    app.run(debug=True)
