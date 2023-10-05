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

class UserPassword(UserBase):
    password: str

class UserLogin(UserPassword):
    token_expiration_seconds: int

    @field_validator('token_expiration_seconds')
    @classmethod
    def token_expiration_seconds_postive(cls, v: int) -> int:
        assert v >= 0, 'must >= 0'
        return v

class UserUpdatePassword(UserPassword):
    new_password: str

class UserCreate(UserInfo, UserPassword):
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

class UserInDB(UserInDBBase, UserPassword):
    """Additional properties stored in DB."""
    pass
