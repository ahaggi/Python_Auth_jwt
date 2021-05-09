from flask import request, render_template, make_response, jsonify, abort
from flask import current_app as app
# from werkzeug.security import generate_password_hash, check_password_hash
# import uuid
from .models import User, UserSchema, sqlalc
from .auth import encode_auth_token, decode_auth_token, token_required

@app.route('/register', methods=['GET', 'POST'])
def signup_user():
    data = request.get_json()

    # hashed_password = generate_password_hash(data['password'], method='sha256')
    hashed_password = data['password']

    user_schema = UserSchema()
    new_user = user_schema.load(data, session=sqlalc.session)
    # Add the user to the database
    sqlalc.session.add(new_user)
    sqlalc.session.commit()
    # Serialize and return the newly created user in the response
    data = user_schema.dump(new_user)

    return jsonify({'message': 'registered successfully'})


@app.route('/login', methods=['GET', 'POST'])
def login_user():

    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    user = User.query.filter(User.username == auth.username).one_or_none()
    #   if check_password_hash(user.password, auth.password):
    if user.password == auth.password:
        #  token = jwt.encode({'public_id': user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        token = encode_auth_token(user.id)
        print(f'token --------------> {token}')
        return jsonify({'token': token})

    return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})


@app.route('/', methods=['GET'])
def home():
    """Create a user via query string parameters."""
    users = User.query.all()
    print(users)
    return {"data": [
        {"username": u.username, "password": u.password, "notes":
         [
            {"id": n.id, "content": n.content, "createdOn": n.createdOn,
                "priority": n.priority, "categoryId": n.categoryId}
            for n in u.notes
            ]
         }
        for u in users
    ]}


@app.route('/users', methods=['GET'])
@token_required
def user_all(current_user):
    """
    This function responds to a request for GET /api/users
    with the complete lists of user
    :return:        JSON string of list of user
    """
    users = User.query.all()
    # Serialize the data for the response
    user_schema = UserSchema(many=True)
    # Serialize objects by passing them to your schema’s dump method, which returns the formatted result
    data = user_schema.dump(users)
    print('***********************************************************')
    print(data)
    print('***********************************************************')
    return jsonify(data)


@app.route('/users/<id>', methods=['GET'])
def user_one(id):
    """
    This function responds to a request for GET /api/users/{id}
    with JUST one matching user
    :param id:      id of the user to find
    :return:        User matching id
    """
    # Build the initial query
    user = User.query.filter(User.id == 1).one_or_none()
    print(id)

    if user is not None:
        # Serialize the data for the response
        user_schema = UserSchema()
        # Serialize objects by passing them to your schema’s dump method, which returns the formatted result
        data = user_schema.dump(user)
        print('***********************************************************')
        print(data)
        print('***********************************************************')
        return jsonify(data)
    # Otherwise, nope, didn't find that user
    else:
        abort(404, f"User not found for id: {id}")
