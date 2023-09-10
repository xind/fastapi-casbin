import logging

from bson import ObjectId
from fastapi import HTTPException, status


logger = logging.getLogger('main')

def valid_user_id(user_id: str) -> bool:
    if not ObjectId.is_valid(user_id):
        msg = "Invalid user ID"
        logger.warning(f"{msg}, user_id={user_id}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
    return True