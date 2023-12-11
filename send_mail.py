from flask import Flask, jsonify

# from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.blocking import BlockingScheduler
from dbModel import db, User
from dotenv import load_dotenv
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os, smtplib

load_dotenv()

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

# app.app_context().push()

db.init_app(app)

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "madhavan.sethu@divum.in"
SMTP_PASSWORD = "Madhav@2492"

# scheduler = BackgroundScheduler()
scheduler = BlockingScheduler()


# @app.route("/sendmail", methods=["GET"])
def send_advertisement_mail():
    with app.app_context():
        users = User.query.all()
        for user in users:
            email = user.email
            print(email)
            subject = "Special Advertisement Offer!"
            body = "Dear user, check out our special offers in this email!"

            message = MIMEMultipart()
            message["From"] = SMTP_USERNAME
            message["To"] = email
            message["Subject"] = subject

            message.attach(MIMEText(body, "plain"))

            try:
                server = smtplib.SMTP("smtp.gmail.com", 587)
                # with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.starttls()
                print(SMTP_USERNAME, SMTP_PASSWORD)
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.sendmail(SMTP_USERNAME, email, message.as_string())
                server.quit()
                # return jsonify({"message": f"Sending Advertisement email to {email}"}), 200
                print(f"Sending Advertisement email to {email}")

            except Exception as e:
                # return (
                #     jsonify({"error": f"Failed to send email to {email}. Error: {str(e)}"})
                # ), 400
                print(f"Failed to send email to {email}. Error: {str(e)}")


scheduler.add_job(func=send_advertisement_mail, trigger="interval", seconds=10)
try:
    scheduler.start()
except (KeyboardInterrupt, SystemExit):
    scheduler.shutdown()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
