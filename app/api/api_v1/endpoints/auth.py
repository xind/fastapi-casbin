import logging

from core.utils import valid_user_id
from core.errors import return_error
from core.config import get_setting

from fastapi import APIRouter, HTTPException, Request, Response, UploadFile, status
from fastapi.responses import ORJSONResponse
from core.authorization import get_privileges_for_user

from models.auth import Privilege, ResponseMessage, Role, RoleCreate, User, UserInfo, UserCreate, UserInDBBase, UserLogin, UserUpdatePassword
from core.authentication import create_access_token, create_refresh_token, get_password_hash, refresh_access_token
from core.database import authenticate_user, delete_icon_in_db, delete_role_in_db, delete_user_in_db, get_icon_in_db, get_privileges_in_db, get_role_by_name, get_roles_in_db, get_user_by_id, get_user_by_username, get_users_in_db, insert_role_into_db, insert_user_into_db, update_role_in_db, update_user_field, update_user_in_db, upsert_icon, valid_user


logger = logging.getLogger('main')
router = APIRouter()

@router.post('/token', summary="Renew the access token", status_code=status.HTTP_201_CREATED, response_model=dict)
async def get_token(request: Request):
    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        access_token = refresh_access_token(refresh_token)
        response = ORJSONResponse(content={"message": "Access token created successfully"})
        response.set_cookie(key="access_token", value=access_token, max_age=get_setting().REFRESH_TOKEN_EXPIRE_MINUTES*60, httponly=True, secure=True)
        return response
    return return_error("Not authenticated", status.HTTP_403_FORBIDDEN)

# TODO: Accept the expire time of refresh token from front-end
@router.post("/login", response_model=User)
async def login(user: UserLogin, response: Response):
    user_in_db = authenticate_user(user.username, user.password)
    if not user_in_db:
        msg = "Invalid username or password"
        logger.warning(f"{msg}, username={user.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=msg)

    user_id = str(user_in_db.id)
    user = User(**user_in_db.model_dump(),
                privileges=get_privileges_for_user(user_id))

    response.set_cookie(key="access_token", value=create_access_token(user_id), max_age=get_setting().REFRESH_TOKEN_EXPIRE_MINUTES*60, httponly=True, secure=True)
    response.set_cookie(key="refresh_token", value=create_refresh_token(user_id), max_age=get_setting().REFRESH_TOKEN_EXPIRE_MINUTES*60, httponly=True, secure=True)
    return user

@router.get("/logout")
async def logout(response: Response):
    response.status_code = status.HTTP_204_NO_CONTENT
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return response

@router.get("/users", response_model=list[UserInDBBase])
async def get_users():
    return get_users_in_db()

@router.post('/users', summary="Create new user", status_code=status.HTTP_201_CREATED, response_model=dict)
async def create_user(user: UserCreate):
    # Querying database to check if user already exist
    if get_user_by_username(user.username):
        msg = "User with the same username already exists"
        logger.warning(f"{msg}, username={user.username}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=msg)

    user.password = get_password_hash(user.password)
    user_id = insert_user_into_db(user)
    return {"message": "User created successfully", "id": user_id}

@router.get("/users/{user_id}", response_model=User)
async def get_user(user_id: str):
    valid_user_id(user_id)
    user_in_db = get_user_by_id(user_id)
    if user_in_db:
        user = User(**user_in_db.model_dump(),
                    privileges=get_privileges_for_user(user_id))
        return user

    msg = "User not found"
    logger.warning(f"{msg}, user_id={user_id}")
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)

@router.put("/users/{user_id}", response_model=ResponseMessage)
async def update_user(user_id: str, user: UserCreate):
    valid_user_id(user_id)
    valid_user(user_id, user.username, user.password)

    result = update_user_in_db(user_id, user)
    if result:
        return {"message": "User updated successfully"}
    return {"message": "User information remains unchanged"}

@router.put("/admin/{user_id}", response_model=ResponseMessage)
async def modify_user_info(user_id: str, user: UserInfo):
    valid_user_id(user_id)
    valid_user(user_id, user.username, '', False)

    result = update_user_in_db(user_id, user)
    if result:
        return {"message": "User updated successfully"}
    return {"message": "User information remains unchanged"}

@router.delete("/users/{user_id}", response_model=ResponseMessage)
async def delete_user(user_id: str):
    valid_user_id(user_id)
    result = delete_user_in_db(user_id)
    if result:
        return {"message": "User deleted successfully"}
    msg = "User not found"
    logger.warning(f"{msg}, user_id={user_id}")
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)

@router.put("/password/{user_id}", summary="Change password", response_model=ResponseMessage)
async def update_password(user_id: str, user: UserUpdatePassword):
    valid_user_id(user_id)
    valid_user(user_id, user.username, user.password)
    original_user = update_user_field(user_id, {"password": get_password_hash(user.new_password)})
    return {"message": "User password updated successfully"}

@router.put("/icons/{user_id}", summary="Upload a JPEG or PNG image file with a size not exceeding 16MB, intended for use as a profile icon", response_model=ResponseMessage)
async def add_user_icon(user_id: str, icon: UploadFile):
    valid_user_id(user_id)

    # Valid the icon image
    if icon.content_type not in ["image/jpeg", "image/png"]:
        msg = "Invalid file type"
        logger.warning(f"{msg}, user_id={user_id}, content_type={icon.content_type}")
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=msg)
    # Get the file size (in bytes)
    icon.file.seek(0, 2)
    file_size = icon.file.tell()
    if file_size > 16 * 1024 * 1024:
        # more than 16 MB
        logger.warning(f"Uploaded file exceeds 16MB limit, user_id={user_id}, file_size={file_size}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file exceeds 16MB limit. Please upload a smaller JPEG or PNG image")
    # move the cursor back to the beginning
    await icon.seek(0)

    original_user = update_user_field(user_id, {"has_icon": True})
    if original_user is None:
        msg = "User not found"
        logger.warning(f"{msg}, user_id={user_id}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)

    success = upsert_icon(user_id, icon.file.read(), icon.content_type.split('/')[-1])
    icon.file.close()

    if success:
        return {"message": "Icon added successfully"}
    else:
        if "has_icon" not in original_user or not original_user["has_icon"]:
            update_user_field(user_id, {"has_icon": False})
        return {"message": "Failed to add icon"}

@router.get("/icons/{user_id}")
async def get_user_icon(user_id: str):
    valid_user_id(user_id)
    icon = get_icon_in_db(user_id)
    if icon:
        return Response(content=icon['icon'], media_type=f"image/{icon['type']}")
    msg = "Icon not found"
    logger.warning(f"{msg}, user_id={user_id}")
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)

@router.delete("/icons/{user_id}", response_model=ResponseMessage)
async def delete_user_icon(user_id: str):
    valid_user_id(user_id)
    result = delete_icon_in_db(user_id)
    if result:
        update_user_field(user_id, {"has_icon": False})
        return {"message": "Icon deleted successfully"}
    msg = "Icon not found"
    logger.warning(f"{msg}, user_id={user_id}")
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)

@router.get("/privileges", response_model=list[Privilege])
async def get_privileges():
    response = get_privileges_in_db()
    return response

@router.get("/roles", response_model=list[RoleCreate])
async def get_roles():
    response = get_roles_in_db()
    return response

@router.get("/roles/{role_name}", response_model=Role)
async def get_role(role_name: str):
    role = get_role_by_name(role_name)
    if role:
        return role
    msg = "Role doesn't exist"
    logger.warning(f"{msg}, role_name={role_name}")
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)

@router.post('/roles', summary="Create new role", status_code=status.HTTP_201_CREATED, response_model=ResponseMessage)
async def create_role(role_create: RoleCreate):
    inserted_id = insert_role_into_db(role_create)
    return {"message": "Role created successfully"}

@router.put("/roles/{role_name}", response_model=ResponseMessage)
async def update_role(role_name: str, role_create: RoleCreate):
    if role_name != role_create.name:
        msg = "Role name change not allowed"
        logger.warning(f"{msg}, role_name={role_name}, new_role_name={role_create.name}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    updated = update_role_in_db(role_create)
    if updated:
        return {"message": "Role updated successfully"}
    return {"message": "Role information remains unchanged"}

@router.delete("/roles/{role_name}", response_model=ResponseMessage)
async def delete_role(role_name: str):
    result = delete_role_in_db(role_name)
    if result:
        return {"message": "Role deleted successfully"}
    msg = "Role doesn't exist"
    logger.warning(f"{msg}, role_name={role_name}")
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
