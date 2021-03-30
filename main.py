from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import random
import string
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from auth import token_required
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = "thisOneIsMySecretStoryLife"
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:Ha&Al@localhost/authentication"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = "users"
    Id = db.Column(db.String(30), unique=True, primary_key=True)
    Username = db.Column(db.String(100), unique=True, nullable=False)
    Password = db.Column(db.String(50), nullable=False)


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(Id=data['public_id']).first()
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)
    return decorator


@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()

    if not auth or not auth['username'] or not auth['password']:
        return make_response('could not verify2', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    user = User.query.filter_by(Username=auth['username']).first()

    if not user:
        return make_response('could not verify1', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    if check_password_hash(user.Password, auth['password']):
        expiredDate = datetime.datetime.utcnow()+datetime.timedelta(hours=12)
        token = jwt.encode(
            {'public_id': user.Id, 'exp': expiredDate}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8'), 'expired at': expiredDate})

    return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})


@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()

        chars = string.ascii_lowercase+string.ascii_uppercase + \
            string.ascii_letters+string.digits
        id = ''.join(random.choice(chars) for i in range(30))
        hashed_password = generate_password_hash(
            data['password'], method='sha256')

        new_user = User(
            Id=id, Username=data['username'], Password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
        except:
            return jsonify({'message': 'you are already login'})

    return jsonify(request.get_json())


@app.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):
    users = User.query.all()
    result = []
    for user in users:
        user_data = {}
        user_data['Id'] = user.Id
        user_data['Username'] = user.Username
        user_data['Password'] = user.Password
        result.append(user_data)
    return jsonify({'users': result})


if __name__ == '__main__':
    app.debug = True
    app.run(port=4000)
