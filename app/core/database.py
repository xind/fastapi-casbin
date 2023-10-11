from functools import lru_cache
import logging
from typing import Any

from bson import Binary, ObjectId
from fastapi import HTTPException, status
from pymongo import MongoClient
from pymongo.results import UpdateResult
from core.authentication import verify_password
from core.authorization import assign_privileges_to_role, get_enforcer, get_privileges_for_role, get_roles_for_user, update_privileges_to_role, update_roles_for_user

from core.config import get_setting, MONGO_URI
from models.auth import Privilege, PrivilegeBase, RoleBase, Role, RoleCreate, UserCreate, UserInDB, UserInDBBase


logger = logging.getLogger('main')
logger_system = logging.getLogger('system')

mongo_client = None

def get_mongo_client():
    global mongo_client
    if not mongo_client:
        mongo_client = MongoClient(MONGO_URI)
        logger_system.info("MongoDB connection established")
    return mongo_client

def close_mongo_connection():
    get_mongo_client().close()
    logger_system.info("MongoDB connection closed")

def get_auth_db():
    return get_mongo_client()[get_setting().AUTH_DATABASE]

def get_users_collection():
    return get_auth_db()[get_setting().USERS_COLLECTION]

def get_icons_collection():
    return get_auth_db()[get_setting().ICONS_COLLECTION]

def get_roles_collection():
    return get_auth_db()[get_setting().ROLES_COLLECTION]

def get_privileges_collection():
    return get_auth_db()[get_setting().PRIVILEGES_COLLECTION]

def _get_specific_values(collection, key: str, match_condition: dict = None) -> list[Any | None]:
    """
    Retrieve specific values of a given key from a MongoDB collection.

    Parameters:
        collection (pymongo.collection.Collection): The MongoDB collection to query.
        key (str): The key for which you want to retrieve specific values.
        match_condition (dict, optional): The optional match condition to filter documents.
                                          Default is None (no filtering).

    Returns:
        list: An array containing the specific values of the key from the matching documents.
    """
    # Aggregation pipeline to optimize the query and retrieve specific values
    pipeline = []

    # Optional match stage to filter documents based on match_condition
    if match_condition:
        pipeline.append({"$match": match_condition})

    # Project stage to include only the specific key
    pipeline.append({"$project": {"_id": 0, "key": f"${key}"}})

    # Group stage to collect values
    pipeline.append({"$group": {"_id": None, "values": {"$push": "$key"}}})

    # Execute the aggregation pipeline and get the result
    result = list(collection.aggregate(pipeline))

    # Access the array of specific values from the result
    if result:
        specific_values_array = result[0]["values"]
        return specific_values_array
    else:
        return []

@lru_cache()
def _get_user(field: str, value: str) -> UserInDB | None:
    if field == '_id':
        value = ObjectId(value)
    try:
        user = get_users_collection().find_one({field: value})
        if user:
            user['roles']= get_roles_for_user(str(user['_id']))
            user = UserInDB(**user, id=user['_id'])
            return user
    except Exception as e:
        msg = "Internal server error"
        logger.error(f"{field}, {value}: {msg}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=msg) from e
    return None

def get_user_by_id(user_id: str) -> UserInDB | None:
    logger.info(f"Database get_user_by_id, user_id={user_id}")
    return _get_user("_id", user_id)

def get_user_by_username(username: str) -> UserInDB | None:
    logger.info(f"Database get_user_by_username, username={username}")
    return _get_user("username", username)

def get_users_in_db() -> list[UserInDBBase]:
    data = get_users_collection().find()
    users = []
    for user in data:
        user['roles'] = get_roles_for_user(str(user['_id']))
        users.append(UserInDBBase(**user, id=user['_id']))
    logger.info("Database get_users_in_db")
    return users

def get_usernames(match_condition: dict = None) -> list[str]:
    logger.info("Database get_usernames, match_condition={match_condition}")
    return _get_specific_values(get_users_collection(), "username", match_condition=match_condition)

def update_user_field(user_id: str, data: dict) -> dict | None:
    """
    Update fields of a user document in MongoDB.

    Parameters:
        user_id (str): The ID of the user document to update.
        data (dict): The fields and values to update.

    Returns:
        dict | None: The original document or None if no document found.
    """
    try:
        result = get_users_collection().find_one_and_update(
            {"_id": ObjectId(user_id)}, {"$set": data}
        )
        if result:
            _get_user.cache_clear()
        logger.info(f"Database update_user_field, user_id={user_id}")
        return result

    except Exception as e:
        msg = "Failed to update user in the database"
        logger.error(f"user_id={user_id}: {msg}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=msg) from e

def _upsert_user(user: UserCreate, user_id: str = None) -> UpdateResult:
    """
    Create or update a user in the MongoDB users collection.

    Parameters:
        user (User): The User object representing the user to be created.
        user_id (str): user_id to be updated

    Returns:
        UpdateResult: The UpdateResult.
    """
    all_roles = set(get_rolenames())
    if not set(user.roles).issubset(all_roles):
        msg = "Role doesn't exist"
        logger.error(f"user_id={user_id}: {msg}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)

    # The user_roles are stored within the 'casbin' collection
    exclude_list = ['roles', 'icon_path']
    if user_id: # perform update
        exclude_list += ['username', 'password']
    user_data = user.model_dump(exclude=exclude_list)
    user_data['disabled'] = False # TODO: not implemented yet

    try:
        result = get_users_collection().update_one(
            {"_id": ObjectId(user_id)}, {"$set": user_data},
            upsert=user_id is None
        )
        _get_user.cache_clear()

        return result

    except Exception as e:
        msg = "Failed to update user in the database"
        logger.error(f"user_id={user_id}: {msg}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=msg) from e

def insert_user_into_db(user: UserCreate) -> str:
    result = _upsert_user(user)
    user_id = str(result.upserted_id)
    update_roles = update_roles_for_user(user_id, user.roles)
    _get_user.cache_clear()

    logger.info(f"Database insert_user_into_db, user_id={user_id}")
    return user_id

def update_user_in_db(user_id: str, user: UserCreate) -> bool:
    result = _upsert_user(user, user_id)
    update_roles = update_roles_for_user(user_id, user.roles)
    _get_user.cache_clear()

    ret = result.modified_count > 0 or update_roles
    logger.info(f"Database update_user_in_db, user_id={user_id}: {ret}")
    return ret

def authenticate_user(username: str, password: str) -> UserInDB | bool:
    user = get_user_by_username(username)
    is_authenticated = user is not None and verify_password(password, user.password)
    msg = f"User authentication, username={username}: {'passed' if is_authenticated else 'failed'}"
    logger.info(msg)
    return user if is_authenticated else False

def valid_user(user_id: str, username: str, password: str, reqired_auth=True) -> UserInDB:
    # Perform data validation and any necessary transformations on user
    user_in_db = get_user_by_id(user_id)
    if user_in_db is None:
        msg = "User not found"
        logger.warning(f"User validation, user_id={user_id}, username={username}: {msg}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
    if username != user_in_db.username:
        msg = "Username change not allowed"
        logger.warning(f"User validation, user_id={user_id}, new_username={username}: {msg}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    if reqired_auth and not authenticate_user(username, password):
        msg = "Invalid username or password"
        logger.warning(f"User validation, user_id={user_id}, username={username}: {msg}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=msg)
    logger.info(f"User validation, user_id={user_id}, username={username}: passed")
    return user_in_db

def get_icon_in_db(user_id: str) -> dict | None:
    ret = None
    result = get_icons_collection().find_one({"user_id": user_id})
    if result:
        ret = result
    logger.info(f"Database get_icon_in_db, user_id={user_id}: {ret is not None}")
    return ret

def upsert_icon(user_id: str, icon: bytes, image_type: str) -> bool:
    """
    Upsert the user's icon in the MongoDB icons collection.

    Parameters:
        user_id (str): The ObjectId (_id) of the user document.
        icon (byes)
        image_type (str)

    Returns:
        success (bool)
    """
    data = {"user_id": user_id, "icon": Binary(icon), "type": image_type}
    match = {'user_id': user_id}

    try:
        result = get_icons_collection().update_one(match, {"$set": data}, upsert=True)
        ret = result.matched_count or result.upserted_id
        logger.info(f"Database upsert_icon, user_id={user_id}: {ret}")
        return ret
    except Exception as e:
        logger.error(f"Database upsert_icon, user_id={user_id}: {e}")
        return False

def delete_icon_in_db(user_id: str) -> bool:
    is_deleted = get_icons_collection().delete_one({"user_id": user_id}).deleted_count > 0
    logger.info(f"Database delete_icon_in_db, user_id={user_id}: {is_deleted}")
    return is_deleted

def delete_user_in_db(user_id: str) -> bool:
    oid = ObjectId(user_id)
    is_deleted = get_users_collection().delete_one({"_id": oid}).deleted_count > 0
    if is_deleted:
        delete_icon_in_db(oid)
        get_enforcer().delete_user(user_id)
        _get_user.cache_clear()
    logger.info(f"Database delete_user_in_db, user_id={user_id}: {is_deleted}")
    return is_deleted

def get_privilege_by_name(name) -> Privilege | None:
    data = get_privileges_collection().find_one({"name": name})
    if data:
        data = Privilege(**data, id=data['_id'])
    logger.info(f"Database get_privilege_by_name, name={name}: {data is not None}")
    return data

def get_privileges_set_in_db(exclude_system=True) -> dict[str, str]:
    result = get_privileges_collection().find()
    privileges = dict()
    for data in result:
        if exclude_system and 'system' in data:
            for action in data['system']:
                data['actions'].remove(action)
            data.pop('system')
        if data['actions']:
            privileges[data['name']] = set(data['actions'])
    logger.info("Database get_privileges_set_in_db")
    return privileges

def check_all_privileges_exist(privileges: list[PrivilegeBase]) -> bool:
    all_exist = True
    name = ''
    all_privileges = get_privileges_set_in_db()
    for privilege in privileges:
        if privilege.name not in all_privileges or not privilege.actions.issubset(all_privileges[privilege.name]):
            name = privilege.name
            all_exist = False
            break
    logger.info(f"Database check_all_privileges_exist, name={name}: {all_exist}")
    return all_exist

def get_privileges_in_db(exclude_system=True) -> list[Privilege]:
    result = get_privileges_collection().find()
    privileges = []
    for data in result:
        if exclude_system and 'system' in data:
            for action in data['system']:
                data['actions'].remove(action)
            data.pop('system')
        if data['actions']:
            privileges.append(Privilege(**data))
    logger.info("Database get_privileges_in_db")
    return privileges

def get_role_by_name(name: str) -> Role | None:
    ret = None
    role = get_roles_collection().find_one({"name": name})
    if role:
        user_ids = get_enforcer().get_users_for_role(name)
        usernames = get_usernames({"_id": {"$in": [ObjectId(_id) for _id in user_ids]}})
        ret = Role(**role, privileges=get_privileges_for_role(name), users=usernames)
    logger.info(f"Database get_role_by_name, name={name}: {ret is not None}")
    return ret

def get_rolenames() -> list[str | None]:
    logger.info("Database get_rolenames")
    return _get_specific_values(get_roles_collection(), "name")

def get_roles_in_db() -> list[RoleCreate | None]:
    role_documents = get_roles_collection().find()
    roles = []
    for document in role_documents:
        roles.append(RoleCreate(**document, id=document['_id'], privileges=get_privileges_for_role(document['name'])))
    logger.info("Database get_roles_in_db")
    return roles

def _upsert_role(role: RoleCreate, insert: bool = False) -> UpdateResult:
    """
    Create or update a role in the MongoDB roles collection.

    Parameters:
        role (RoleCreate): The RoleCreate object representing the role to be created/updated.
        insert (bool): create the role document if not found when set to True, update the role document otherwise.

    Returns:
        UpdateResult: The UpdateResult.
    """
    # Querying database to check if role already exist
    if not check_all_privileges_exist(role.privileges):
        msg = "Privilege doesn't exist"
        logger.error(f"Database _upsert_role, name={role.name}: {msg}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)

    try:
        # Convert the Role object to a dictionary and insert into the collection
        result = get_roles_collection().update_one(
            {"name": role.name},
            {"$set": RoleBase(**role.model_dump()).model_dump()},
            upsert=insert
        )
        return result

    except Exception as e:
        msg = "Failed to insert role into the database"
        logger.error(f"Database _upsert_role, name={role.name}: {msg}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=msg) from e

def insert_role_into_db(role: RoleCreate) -> str:
    """
    Create a new role in the MongoDB roles collection.

    Parameters:
        role (RoleCreate): The RoleCreate object representing the role to be created.

    Returns:
        ObjectId (str): The inserted role's ObjectId (_id).
    """
    # TODO: add default privileges to the role?
    # querying database to check if role already exist
    if role.name == get_setting().ROLE_SYSTEM:
        msg = "Access Forbidden"
        logger.error(f"Database insert_role_into_db, name={role.name}: {msg}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=msg)
    if get_role_by_name(role.name):
        msg = "Role with the same name already exists"
        logger.error(f"Database insert_role_into_db, name={role.name}: {msg}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=msg)

    try:
        result = _upsert_role(role, insert=True)
        inserted_id = str(result.upserted_id)
        if inserted_id:
            assign_privileges_to_role(role.name, role.privileges)
        logger.info(f"Database insert_role_into_db, name={role.name}, id={inserted_id}")
        return inserted_id
    except Exception as e:
        msg = "Failed to insert role into the database"
        logger.error(f"Database insert_role_into_db, name={role.name}: {msg}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=msg) from e

def update_role_in_db(role: RoleCreate) -> bool:
    # Querying database to check if role exist
    existing_role = get_role_by_name(role.name)
    if existing_role is None:
        msg = "Role not found"
        logger.error(f"Database update_role_in_db, name={role.name}: {msg}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)

    if role.name in {get_setting().ROLE_SYSTEM, get_setting().ROLE_ADMIN}:
        msg = "Access Forbidden"
        logger.error(f"Database update_role_in_db, name={role.name}: {msg}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=msg)

    result = _upsert_role(role, insert=False)
    is_matched = result.matched_count > 0
    is_updated = False
    if is_matched:
        update_privileges = update_privileges_to_role(role.name, role.privileges)
        is_updated = result.modified_count > 0 or update_privileges
    logger.info(f"Database update_role_in_db, name={role.name}, matched={is_matched}, updated={is_updated}"
)
    return is_matched and is_updated

def delete_role_in_db(role_name: str) -> bool:
    users = get_enforcer().get_users_for_role(role_name)
    if role_name in {get_setting().ROLE_SYSTEM, get_setting().ROLE_ADMIN}:
        msg = "Access Forbidden"
        logger.error(f"Database delete_role_in_db, name={role_name}: {msg}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=msg)
    if users:
        # TODO: force delete?
        msg = "Role users is not empty"
        logger.error(f"Database delete_role_in_db, name={role_name}: {msg}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    is_deleted = get_roles_collection().delete_one({"name": role_name}).deleted_count > 0
    if is_deleted:
        get_enforcer().delete_role(role_name)
    logger.info(f"Database delete_role_in_db, name={role_name}: {is_deleted}")
    return is_deleted
