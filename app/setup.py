import logging
import json

from core.authentication import get_password_hash
from core.authorization import get_enforcer, get_default_privileges, init_system_privileges
from core.config import ALLOWED_PRIVILEGE_ACTIONS, DEFAULT_ROLE_PRIVILEGES_JSON_PATH, get_logging_config, get_setting

from core.database import get_auth_db, get_icons_collection, get_privileges_collection, get_roles_collection, get_user_by_username, get_users_collection

logging.config.dictConfig(get_logging_config())
logger_system = logging.getLogger('system')

user_roles = {
    get_setting().USER_ADMIN: get_setting().ROLE_ADMIN,
    get_setting().USER_USER: get_setting().ROLE_USER,
    get_setting().USER_GUEST: get_setting().ROLE_GUEST,
}

# Dictionary containing collection names as keys and initial data as values
initial_data_by_collection = {
    get_setting().USERS_COLLECTION: [
        {"username": u, "password": get_password_hash(u), "disabled": False} for u in user_roles.keys()
    ],
    get_setting().ROLES_COLLECTION: [
        {"name": user_roles[u], "description": user_roles[u]} for u in user_roles.keys()
    ],
    get_setting().PRIVILEGES_COLLECTION: get_default_privileges(),
}

def get_role_privileges_from_file():
    # Actions in the “system” are granted to all users by default without the need for explicit user actions or configurations.
    with open(DEFAULT_ROLE_PRIVILEGES_JSON_PATH) as file:
        data = json.load(file)
    return data['role_privileges']

def init_policies():
    if get_enforcer().get_policy():
        logger_system.warning(f"Policies initialization canceled, policies already exist")
        return False

    # Add role-privileges
    for rps in get_role_privileges_from_file():
        for privilege in rps["privileges"]:
            for action in privilege["actions"]:
                if action not in ALLOWED_PRIVILEGE_ACTIONS:
                    raise ValueError
                get_enforcer().add_policy(rps["role"], privilege["name"], action)

    # Add user-roles
    for username in user_roles:
        user = get_user_by_username(username)
        get_enforcer().add_role_for_user(str(user.id), user_roles[username])
    logger_system.info("Policies initialized")

def init_database():
    auth_db = get_auth_db()

    # create index and unique keys
    get_users_collection().create_index("username", unique=True)
    get_roles_collection().create_index("name", unique=True)
    get_privileges_collection().create_index("name", unique=True)
    get_icons_collection().create_index("user_id", unique=True)

    # Insert initial data into each collection
    for collection_name, data in initial_data_by_collection.items():
        collection = auth_db[collection_name]
        if collection.count_documents({}) == 0:
            collection.insert_many(data)
            logger_system.info(f"Initial data inserted for {collection_name} collection.")


if __name__ == "__main__":
    init_database()
    init_policies()
    init_system_privileges()
