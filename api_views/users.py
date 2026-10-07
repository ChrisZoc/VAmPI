import re
import jsonschema
import jwt

from config import db, vuln_app
from api_views.json_schemas import *
from flask import jsonify, Response, request, json
from models.user_model import User
from app import vuln


def error_message_helper(msg):
    if isinstance(msg, dict):
        return '{ "status": "fail", "message": "' + msg['error'] + '"}'
    else:
        return '{ "status": "fail", "message": "' + msg + '"}'


def get_all_users():
    return_value = jsonify({'users': User.get_all_users()})
    return return_value


def debug():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")

    user = User.query.filter_by(username=resp['sub']).first()
    if not user or not user.admin:
        return Response(error_message_helper("Only Admins may view debug data!"), 403, mimetype="application/json")

    return jsonify({'users': User.get_all_users_debug()})

def me():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        user = User.query.filter_by(username=resp['sub']).first()
        responseObject = {
            'status': 'success',
            'data': {
                'username': user.username,
                'email': user.email,
                'admin': user.admin
            }
        }
        return Response(json.dumps(responseObject), 200, mimetype="application/json")
        

def get_by_username(username):
    user = User.get_user(username)
    if user:
        return jsonify(user.json())
    else:
        return Response(error_message_helper("User not found"), 404, mimetype="application/json")


def register_user():
    request_data = request.get_json()
    if request_data and 'admin' in request_data:
        return Response(error_message_helper("Unexpected field: admin"), 400, mimetype="application/json")
    # check if user already exists
    user = User.query.filter_by(username=request_data.get('username')).first()
    if not user:
        try:
            # validate the data are in the correct form
            jsonschema.validate(request_data, register_user_schema)
            user = User(username=request_data['username'], password=request_data['password'],
                        email=request_data['email'])
            db.session.add(user)
            db.session.commit()

            responseObject = {
                'status': 'success',
                'message': 'Successfully registered. Login to receive an auth token.'
            }

            return Response(json.dumps(responseObject), 200, mimetype="application/json")
        except jsonschema.exceptions.ValidationError as exc:
            return Response(error_message_helper(exc.message), 400, mimetype="application/json")
    else:
        return Response(error_message_helper("User already exists. Please Log in."), 200, mimetype="application/json")


def login_user():
    request_data = request.get_json()

    try:
        # validate the data are in the correct form
        jsonschema.validate(request_data, login_user_schema)
        # fetching user data if the user exists
        user = User.query.filter_by(username=request_data.get('username')).first()
        if user and user.check_password(request_data.get('password')):
            auth_token = user.encode_auth_token(user.username)
            responseObject = {
                'status': 'success',
                'message': 'Successfully logged in.',
                'auth_token': auth_token
            }
            return Response(json.dumps(responseObject), 200, mimetype="application/json")
        return Response(error_message_helper("Username or Password Incorrect!"), 401,
                        mimetype="application/json")
    except jsonschema.exceptions.ValidationError as exc:
        return Response(error_message_helper(exc.message), 400, mimetype="application/json")
    except:
        return Response(error_message_helper("An error occurred!"), 400, mimetype="application/json")


def token_validator(auth_header):
    auth_token = ""
    if auth_header:
        parts = auth_header.split(" ")
        if len(parts) == 2 and parts[0].lower() == 'bearer':
            auth_token = parts[1]
    if auth_token:
        return User.decode_auth_token(auth_token)
    else:
        return {'error': 'Invalid token. Please log in again.'}


def update_email(username):
    request_data = request.get_json()
    try:
        jsonschema.validate(request_data, update_email_schema)
    except:
        return Response(error_message_helper("Please provide a proper JSON body."), 400, mimetype="application/json")
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        user = User.query.filter_by(username=resp['sub']).first()
        if not user:
            return Response(error_message_helper("User not found"), 404, mimetype="application/json")
        if not (user.admin or user.username == username):
            return Response(error_message_helper("Only the account owner or an admin may update email."), 403,
                            mimetype="application/json")

        regex = r'^[a-z0-9]+[._]?[a-z0-9]+@\w+[.]\w{2,3}$'
        if re.search(regex, request_data.get('email')):
            target_user = User.query.filter_by(username=username).first()
            if not target_user:
                return Response(error_message_helper("User not found"), 404, mimetype="application/json")
            target_user.email = request_data.get('email')
            db.session.commit()
            responseObject = {
                'status': 'success',
                'data': {
                    'username': target_user.username,
                    'email': target_user.email
                }
            }
            return Response(json.dumps(responseObject), 204, mimetype="application/json")

        return Response(error_message_helper("Please Provide a valid email address."), 400,
                        mimetype="application/json")


def update_password(username):
    request_data = request.get_json()
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        if request_data.get('password'):
            current_user = User.query.filter_by(username=resp['sub']).first()
            if not current_user:
                return Response(error_message_helper("User Not Found"), 404, mimetype="application/json")
            if not (current_user.admin or current_user.username == username):
                return Response(error_message_helper("Only the account owner or an admin may update passwords."), 403,
                                mimetype="application/json")
            user = User.query.filter_by(username=username).first()
            if not user:
                return Response(error_message_helper("User Not Found"), 404, mimetype="application/json")
            user.set_password(request_data.get('password'))
            db.session.commit()
            responseObject = {
                'status': 'success',
                'Password': 'Updated.'
            }
            return Response(json.dumps(responseObject), 204, mimetype="application/json")
        else:
            return Response(error_message_helper("Malformed Data"), 400, mimetype="application/json")


def delete_user(username):
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        user = User.query.filter_by(username=resp['sub']).first()
        if user.admin:
            if bool(User.delete_user(username)):
                responseObject = {
                    'status': 'success',
                    'message': 'User deleted.'
                }
                return Response(json.dumps(responseObject), 200, mimetype="application/json")
            else:
                return Response(error_message_helper("User not found!"), 404, mimetype="application/json")
        else:
            return Response(error_message_helper("Only Admins may delete users!"), 401, mimetype="application/json")
