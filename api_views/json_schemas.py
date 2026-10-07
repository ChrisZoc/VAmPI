register_user_schema = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "username": {"type": "string", "minLength": 3, "maxLength": 128},
        "password": {"type": "string", "minLength": 8, "maxLength": 128},
        "email": {"type": "string", "minLength": 3, "maxLength": 128}
    },
    "required": ["username", "password", "email"]
}

login_user_schema = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "username": {"type": "string", "minLength": 3, "maxLength": 128},
        "password": {"type": "string", "minLength": 1, "maxLength": 128}
    },
    "required": ["username", "password"]
}

update_email_schema = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "email": {"type": "string", "minLength": 3, "maxLength": 128}
    },
    "required": ["email"]
}

add_book_schema = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "book_title": {"type": "string", "minLength": 1, "maxLength": 128},
        "secret": {"type": "string", "minLength": 1, "maxLength": 128}
    },
    "required": ["book_title", "secret"]
}
