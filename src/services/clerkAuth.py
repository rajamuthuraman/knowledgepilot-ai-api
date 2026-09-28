from src.config.index import appConfig
from src.config.logging import get_logger
from fastapi import Request, HTTPException

from clerk_backend_api import Clerk
from clerk_backend_api.security import authenticate_request
from clerk_backend_api.security.types import AuthenticateRequestOptions

logger = get_logger(__name__)


def get_current_user_clerk_id(request: Request):
    try:
        sdk = Clerk(appConfig["clerk_secret_key"])

        # request_state = JWT Token
        request_state = sdk.authenticate_request(
            request,
            options=AuthenticateRequestOptions(authorized_parties=[appConfig["domain"]]),
        )

        if not request_state.is_signed_in:
            logger.warning("clerk_not_signed_in", reason=str(request_state.reason))
            raise HTTPException(status_code=401, detail="User is not signed in")

        clerk_id = request_state.payload.get("sub")

        if not clerk_id:
            raise HTTPException(status_code=401, detail="Clerk ID not found in token")

        return clerk_id

    except HTTPException:
        raise

    except Exception as e:
        logger.error("clerk_sdk_failed", error=str(e), exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Clerk SDK Failed. {str(e)}",
        )
