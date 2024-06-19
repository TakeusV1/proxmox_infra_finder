from config import *
from flask import Flask, request

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.config.from_object(Configuration)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer(),primary_key=True,unique=True)
    username = db.Column(db.String(16))
    password = db.Column(db.String(32),unique=True)
    admin = db.Column(db.Boolean())
    
with app.app_context():
    db.create_all()

@app.route('/',methods=['GET','POST'])
def setup():
    if request.method == "POST":
        db.session.add(User(username=request.form["username"],password=generate_password_hash(request.form["password"]),admin=1))
        db.session.commit()
        return 'Done, you can delete setup.py'
    return "<h1>admin user creation</h1><br><form method='post'><input name='username' placeholder='username'><br><input type='password' name='password' placeholder='password'><br><button type='submit'>submit</button></form>"

if __name__ == '__main__':
    app.run(host=app_ip, port=app_port, debug=app_debug)