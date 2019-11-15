import uuid


database = {
    "users": {
        "admin": {
            "password": "my_secret_password",
            "role": "admin",
            "email": "admin@acme.come",
        }
    },
    "secrets": {
        "folder1": {
            "thycotic_user@target": {
                "id": 1,
                "username": "thycotic_user",
                "password": "secret_password",
                "machine": "target.acme.com",
                "notes": "",
                "name": "thycotic_user@target",
                "active": True,
                "restricted": False,

            },
            "other_user@target": {
                "id": 2,
                "username": "thycotic_user",
                "password": "selfecret_password",
                "machine": "restricted_target.acme.com",
                "notes": "",
                "name": "other_user@target",
                "active": False,
                "restricted": True
            }
        },
        "folder2": {}
    },
}
