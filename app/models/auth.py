from core.config import get_setting
from pydantic import BaseModel, ConfigDict, EmailStr, field_validator

from models.ObjectId import PyObjectId


class ResponseMessage(BaseModel):
    message: str

class PrivilegeBase(BaseModel):
    name: str
    actions: set[str]

class Privilege(PrivilegeBase):
    description: str

class PrivilegeInDB(Privilege):
    system: set[str] | None = None

class RoleBase(BaseModel):
    name: str
    description: str

    @field_validator('name')
    @classmethod
    def name_alphanumeric_space(cls, v: str) -> str:
        is_alphanumeric = v.replace(' ', '').isalnum()
        assert is_alphanumeric, 'must be alphanumeric or space'
        return v

class RoleCreate(RoleBase):
    privileges: list[PrivilegeBase] | None = None

class Role(RoleCreate):
    users: list[str]

class UserBase(BaseModel):
    """Shared properties."""
    username: str

    @field_validator('username')
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        assert v.isalnum(), 'must be alphanumeric'
        return v

class UserInfo(UserBase):
    roles: list[str]
    email: EmailStr | None = None
    firstname: str | None = None
    lastname: str | None = None
    disabled: bool = False

class UserLogin(UserBase):
    password: str

class UserUpdatePassword(UserLogin):
    new_password: str

class UserCreate(UserInfo, UserLogin):
    """Properties to receive on item creation."""
    pass

class UserInDBBase(UserInfo):
    """Properties shared by models stored in DB - !exposed in base/create/update."""
    id: PyObjectId
    has_icon: bool = False

    model_config = ConfigDict(arbitrary_types_allowed=True)

class User(UserInDBBase):
    """Properties to return to client."""
    privileges: list[PrivilegeBase]

class UserInDB(UserInDBBase, UserLogin):
    """Additional properties stored in DB."""
    pass
