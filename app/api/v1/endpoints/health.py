from fastapi import APIRouter, status

router = APIRouter(
    prefix="/health",
    tags=["API Health"]
)


@router.get("/")
async def health_check():
    """
    Endpoint to check health of this API.
    Returned OK status if API is working well.
    """
    return {"status": "OK", "message": "VESTA API is working well."}