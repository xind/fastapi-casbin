import json
import logging
import random
import re
import string
from fastapi import Request, status
from casbin import Enforcer
import casbin_pymongo_adapter
import jwt
from starlette.middleware.base import BaseHTTPMiddleware

from core.config import CASBIN_MODEL_PATH, DEFAULT_PRIVILEGES_JSON_PATH, get_setting, MONGO_URI
from core.errors import return_error
from models.auth import PrivilegeBase


logger = logging.getLogger('main')
logger_system = logging.getLogger('system')
logger_access = logging.getLogger('access')

enforcer = None

def get_enforcer():
    global enforcer
    if not enforcer:
        adapter = casbin_pymongo_adapter.Adapter(MONGO_URI, get_setting().AUTH_DATABASE)
        enforcer = Enforcer(CASBIN_MODEL_PATH, adapter, True)
        logger_system.info("Enforcer initialized")

    return enforcer

def get_default_privileges() -> dict:
    with open(DEFAULT_PRIVILEGES_JSON_PATH) as file:
        data = json.load(file)
    return data['privileges']

def init_system_privileges() -> None:
    privileges = get_default_privileges()
    for privilege in privileges:
        if 'system' in privilege and privilege['system']:
            for action in privilege['system']:
                get_enforcer().add_policy(get_setting().ROLE_SYSTEM, privilege['name'], action)
    logger_system.info("System privileges initialized")
    return None

class RBACMiddleware(BaseHTTPMiddleware):
    """In a FastAPI/Starlette middleware, raise exceptions will leading to Exception in ASGI application error on server side, and hence, an Internal Server Error would be returned to the client."""
    logger_system.info("RBACMiddleware initialized")

    async def dispatch(self, request: Request, call_next):
        idem = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        # The pattern to match the prefixes
        pattern = r"/api/v\d+(\.\d+)?"

        # Get the route path from the request
        resource = re.sub(pattern, "", request.url.path)
        action = request.method

        logger.info(f"Request received for endpoint: {request.method} {request.url.path}")
        logger_access.info(f"Performing RBAC authorization check rid={idem}, {request.client.host}, {resource}, {action}")

        if get_enforcer().enforce(get_setting().ROLE_SYSTEM, resource, action):
            logger_access.info(f"Proceed system API, rid={idem}")
            # Proceed with the request of system endpoints
            response = await call_next(request)
            logger.info(f"Request processed for endpoint: {request.method} {request.url.path}, Status Code: {response.status_code}")
            return response

        # Perform authentication and check the token validity here
        access_token = request.cookies.get("access_token")
        user_id = None
        if access_token is not None:
            try:
                payload = jwt.decode(access_token, get_setting().JWT_SECRET_KEY, algorithms=[get_setting().JWT_ALGORITHM])
                user_id = payload['sub']
            except jwt.ExpiredSignatureError:
                msg = "Token has expired"
                logger_access.info(f"{msg}, rid={idem}")
                return return_error(msg, status.HTTP_401_UNAUTHORIZED)
            except jwt.InvalidTokenError:
                msg = "Invalid token"
                logger_access.warning(f"{msg}, rid={idem}")
                return return_error(msg, status.HTTP_401_UNAUTHORIZED)
        else:
            logger_access.warning(f"access_token is None, rid={idem}")
            return return_error("Not authenticated", status.HTTP_403_FORBIDDEN)

        # Perform the RBAC authorization check
        if not get_enforcer().enforce(user_id, resource, action):
            msg = "Access Forbidden"
            logger_access.warning(f"{msg}, rid={idem}, user_id={user_id}")
            return return_error(msg, status.HTTP_403_FORBIDDEN)
        logger_access.info(f"Authorized: rid={idem}, user_id={user_id}")

        # Proceed with the request if the authorization check passes
        response = await call_next(request)
        logger.info(f"Request processed for endpoint: {request.method} {request.url.path}, Status Code: {response.status_code}")
        return response

def _get_privileges(role_name: str = None, user_id: str = None) -> list[PrivilegeBase]:
    if role_name:
        permissions = get_enforcer().get_permissions_for_user(role_name)
    elif user_id:
        permissions = get_enforcer().get_implicit_permissions_for_user(user_id)
    else:
        permissions = get_enforcer().get_policy()

    logger_access.info(f"_get_privileges, role_name={role_name}, user_id={user_id}")
    privileges = []
    curr_privileges = dict()
    for i in range(len(permissions)):
        permission = permissions[i]
        privilege = permission[1]
        action = permission[2]
        if privilege in curr_privileges:
            privileges[curr_privileges[privilege]].actions.add(action)
        else:
            curr_privileges[privilege] = len(privileges)
            privileges.append(PrivilegeBase(name=privilege, actions={action}))
    return privileges

def get_privileges_for_role(role_name: str) -> list[PrivilegeBase]:
    return _get_privileges(role_name=role_name)

def get_privileges_for_user(user_id: str) -> list[PrivilegeBase]:
    return _get_privileges(user_id=user_id)

def assign_privileges_to_role(role_name: str, privileges: list[PrivilegeBase]):
    for privilege in privileges:
        for action in privilege.actions:
            logger_access.info(f"assign_privileges_to_role, role_name={role_name}: {privilege.name}, {action}")
            get_enforcer().add_policy(role_name, privilege.name, action)

def update_privileges_to_role(role_name: str, privileges: list[PrivilegeBase]) -> bool:
    update = False
    curr_permissions = set(tuple(p[1:]) for p in get_enforcer().get_permissions_for_user(role_name))

    # Add new privileges
    for privilege in privileges:
        for action in privilege.actions:
            p = (privilege.name, action)
            if p in curr_permissions:
                curr_permissions.remove(p)
            else:
                update = True
                logger_access.info(f"update_privileges_to_role, role_name={role_name}: add {privilege.name}, {action}")
                get_enforcer().add_policy(role_name, privilege.name, action)

    # Remove old privileges
    for permission in curr_permissions:
        update = True
        logger_access.info(f"update_privileges_to_role, role_name={role_name}: remove {permission}")
        get_enforcer().remove_policy(role_name, permission[0], permission[1])

    return update

def get_roles_for_user(user_id: str) -> list[str]:
    logger_access.info(f"get_roles_for_user, user_id={user_id}")
    return get_enforcer().get_roles_for_user(user_id)

def update_roles_for_user(user_id: str, roles: list) -> bool:
    roles = set(roles)
    existing_roles = set(get_enforcer().get_roles_for_user(user_id))
    logger_access.info(f"update_roles_for_user, user_id={user_id}")
    if roles == existing_roles:
        return False

    for role in roles.union(existing_roles):
        if role in roles:
            get_enforcer().add_role_for_user(user_id, role)
        else:
            get_enforcer().delete_role_for_user(user_id, role)
    return True
