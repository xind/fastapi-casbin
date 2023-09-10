import logging

from fastapi import FastAPI
from fastapi.responses import ORJSONResponse
from starlette.exceptions import HTTPException
from starlette.middleware.cors import CORSMiddleware
from starlette.status import HTTP_422_UNPROCESSABLE_ENTITY

from api.api_v1.api import api_router
from core.config import get_logging_config, get_setting, ALLOWED_HOSTS
from core.errors import http_422_error_handler, http_error_handler

from core.database import get_mongo_client
from core.authorization import RBACMiddleware

from api.api_v1.api import api_router

logging.config.dictConfig(get_logging_config())
logger_system = logging.getLogger('system')

app = FastAPI(title=get_setting().PROJECT_NAME, version=get_setting().PROJECT_VERSION, default_response_class=ORJSONResponse)

if not ALLOWED_HOSTS:
    ALLOWED_HOSTS = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_HOSTS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(RBACMiddleware)

app.add_exception_handler(HTTPException, http_error_handler)
app.add_exception_handler(HTTP_422_UNPROCESSABLE_ENTITY, http_422_error_handler)

app.include_router(api_router, prefix=get_setting().API_V1_STR)


@app.on_event("startup")
async def startup():
    logger_system.info("Fastapi startup")

@app.on_event("shutdown")
async def shutdown_event():
    get_mongo_client().close()
    logger_system.info("Fastapi shutdown")