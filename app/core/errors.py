import logging
from collections.abc import Iterable

from fastapi.responses import ORJSONResponse
from fastapi.openapi.constants import REF_PREFIX
from fastapi.openapi.utils import (
    validation_error_definition,
    validation_error_response_definition,
)
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.status import HTTP_422_UNPROCESSABLE_ENTITY


logger = logging.getLogger('main')

def return_error(errors, status_code):
    logger.error(f"Error response generated with status code {status_code}: {errors}")
    return ORJSONResponse({"errors": errors}, status_code=status_code)

async def http_error_handler(request: Request, exc: HTTPException) -> ORJSONResponse:
    logger.error(f"Error response generated with status code {exc.status_code}: {exc.detail}")
    return return_error(exc.detail, exc.status_code)


async def http_422_error_handler(request: Request, exc: HTTPException) -> ORJSONResponse:
    """
    Handler for 422 error to transform default pydantic error object to gothinkster format
    """

    errors = {"body": []}

    if isinstance(exc.detail, Iterable) and not isinstance(
        exc.detail, str
    ):  # check if error is pydantic's model error
        for error in exc.detail:
            error_name = ".".join(
                error["loc"][1:]
            )  # remove 'body' from path to invalid element
            errors["body"].append({error_name: error["msg"]})
    else:
        errors["body"].append(exc.detail)

    return return_error(errors, HTTP_422_UNPROCESSABLE_ENTITY)


validation_error_definition["properties"] = {
    "body": {"title": "Body", "type": "array", "items": {"type": "string"}}
}

validation_error_response_definition["properties"] = {
    "errors": {
        "title": "Errors",
        "type": "array",
        "items": {"$ref": REF_PREFIX + "ValidationError"},
    }
}