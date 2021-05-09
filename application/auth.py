import jwt
from functools import wraps
import datetime
from flask import request, make_response #, jsonify, abort
from flask import current_app as app

from .models import User
def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']
        if not token:
            return jsonify({'message': 'a valid token is missing'})
        res = decode_auth_token(token)

        if 'errMsg' in res.keys():
            return make_response(res['errMsg'] , res['code'] )

        current_user = User.query.filter(User.id == res['sub']).first()
        return f(current_user, *args, **kwargs)
    return decorator

def encode_auth_token(user_id):
    """
    Generates the Auth Token
    :return: string
    """
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
    except Exception as e:
        return e


def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: integer|string
    """
    try:
        payload = jwt.decode(
            auth_token,
            app.config['SECRET_KEY'],
            algorithms="HS256"
        )
        return payload
    except jwt.ExpiredSignatureError:
        return {'errMsg': 'Signature expired. Please log in again.', 'code': 401}
    except jwt.InvalidTokenError:
        return {'errMsg': 'Invalid token. Please log in again.', 'code': 403}
