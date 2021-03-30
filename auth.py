from functools import wraps


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None
        print ()
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'})

        try:
            data = jwt.decode(token, app.config[SECRET_KEY])
            current_user = Users.query.filter_by(Id=data['Id']).first()
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)
    return decorator
