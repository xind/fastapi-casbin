import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic.fields import FieldInfo
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource


ALLOWED_HOSTS = ['*']
ALLOWED_PRIVILEGE_ACTIONS = {'GET', 'POST', 'PUT', 'DELETE'}

CASBIN_MODEL_PATH = "/app/data/casbin_model.conf"
DEFAULT_PRIVILEGES_JSON_PATH = "/app/data/default_privileges.json"
DEFAULT_ROLE_PRIVILEGES_JSON_PATH = "/app/data/default_role_privileges.json"

class JsonConfigSettingsSource(PydanticBaseSettingsSource):
    """
    A simple settings source class that loads variables from a JSON file
    at the project's root.

    Here we happen to choose to use the `env_file_encoding` from Config
    when reading `config.json`
    """

    def get_field_value(
        self, field: FieldInfo, field_name: str
    ) -> tuple[Any, str, bool]:
        encoding = self.config.get('env_file_encoding')
        file_content_json = json.loads(
            Path(DEFAULT_PRIVILEGES_JSON_PATH).read_text(encoding)
        )
        field_value = file_content_json.get(field_name)
        return field_value, field_name, False

    def prepare_field_value(
        self, field_name: str, field: FieldInfo, value: Any, value_is_complex: bool
    ) -> Any:
        return value

    def __call__(self) -> dict[str, Any]:
        d: dict[str, Any] = {}

        for field_name, field in self.settings_cls.model_fields.items():
            field_value, field_key, value_is_complex = self.get_field_value(
                field, field_name
            )
            field_value = self.prepare_field_value(
                field_name, field, field_value, value_is_complex
            )
            if field_value is not None:
                d[field_key] = field_value

        return d

class Settings(BaseSettings):

    API_V1_STR: str = "/api/v1"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30  # 30 minutes
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7 # 7 days
    JWT_ALGORITHM: str = "HS256"
    JWT_SECRET_KEY: str = "secret" # TODO: change this with stronger secret
    JWT_REFRESH_SECRET_KEY: str = "another_secret" # TODO: change this with stronger secret

    PROJECT_NAME: str = "FastAPI RBAC application"
    PROJECT_VERSION: str = "0.1.0"

    MONGO_HOSTNAME: str
    MONGO_PORT: int = 27017
    MONGO_INITDB_ROOT_USERNAME: str
    MONGO_INITDB_ROOT_PASSWORD: str

    AUTH_DATABASE: str = "auth"
    USERS_COLLECTION: str = "users"
    ICONS_COLLECTION: str = "icons"
    ROLES_COLLECTION: str = "roles"
    PRIVILEGES_COLLECTION: str = "privileges"

    # Default users
    USER_ADMIN: str = 'admin'
    USER_USER: str = 'user'
    USER_GUEST: str = 'guest'
    # Default roles
    ROLE_SYSTEM: str = '_system' # internal use
    ROLE_ADMIN: str = 'Administrator'
    ROLE_USER: str = 'Standard User'
    ROLE_GUEST: str = 'Guest'


@lru_cache(maxsize=1)
def get_setting():
    return Settings()

MONGO_URI = f'mongodb://{get_setting().MONGO_INITDB_ROOT_USERNAME}:{get_setting().MONGO_INITDB_ROOT_PASSWORD}@{get_setting().MONGO_HOSTNAME}:27017'

def get_logging_config():
    with open('data/logging_config.yaml', 'r') as file:
        config = yaml.safe_load(file)
        return config