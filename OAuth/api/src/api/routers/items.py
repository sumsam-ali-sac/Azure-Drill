from fastapi import APIRouter, Request, HTTPException, status
from fastapi_cache.decorator import cache
from src.api.common.logging.logging_manager import get_logger
from src.api.common.telemetry import trace_operation
from src.api.config import get_settings
from src.api.models.item import Item
from src.api.core.dependencies import get_rate_limiter
from fastapi import Depends
import time

router = APIRouter(prefix="/items", tags=["items"])
_logger = get_logger(__name__)
settings = get_settings()


@router.get("/{item_id}", dependencies=[Depends(get_rate_limiter)])
@cache(expire=settings.redis.REDIS_TIMEOUT)
async def read_item(item_id: int, request: Request):
    _logger.info(
        f"Received request for item_id: {item_id}",
        extra={"request_id": request.state.request_id},
    )
    with trace_operation(
        "process_item_logic",
        {"item.id": item_id, "request.id": request.state.request_id},
    ) as span:
        _logger.debug(
            f"Starting processing logic for item {item_id} within a custom span.",
            extra={"request_id": request.state.request_id},
        )
        if item_id % 2 != 0:
            time.sleep(settings.performance_monitoring.SLOW_REQUEST_THRESHOLD + 0.1)
            _logger.warning(
                f"Item {item_id} is odd, performing special handling.",
                extra={"request_id": request.state.request_id},
            )
            span.set_attribute("item.type", "odd")
        else:
            time.sleep(0.05)
            _logger.info(
                f"Item {item_id} is even, standard processing.",
                extra={"request_id": request.state.request_id},
            )
            span.set_attribute("item.type", "even")
        if item_id < 0:
            _logger.error(
                f"Invalid item_id: {item_id}. Must be non-negative.",
                extra={"request_id": request.state.request_id},
            )
            span.set_attribute("error", True)
            span.record_exception(ValueError("Item ID cannot be negative"))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Item ID cannot be negative",
            )
        _logger.debug(
            f"Finished processing logic for item {item_id}.",
            extra={"request_id": request.state.request_id},
        )
    _logger.info(
        f"Successfully processed item {item_id}.",
        extra={"request_id": request.state.request_id},
    )
    return {
        "item_id": item_id,
        "status": "processed",
        "request_id": request.state.request_id,
    }


@router.post("/data")
async def post_data(item: Item, request: Request):
    _logger.info(
        f"Received data: {item.name}", extra={"request_id": request.state.request_id}
    )
    if item.sensitive_info:
        _logger.warning(
            "Sensitive information detected in payload.",
            extra={
                "request_id": request.state.request_id,
                "sensitive_data_present": True,
            },
        )
    with trace_operation(
        "store_item_data",
        {"item.name": item.name, "request.id": request.state.request_id},
    ):
        time.sleep(0.02)
        _logger.debug(
            "Item data stored successfully.",
            extra={"request_id": request.state.request_id},
        )
    return {
        "message": f"Item '{item.name}' received.",
        "request_id": request.state.request_id,
    }


@router.get("/error")
async def trigger_error(request: Request):
    _logger.error(
        "Triggering an intentional error.",
        extra={"request_id": request.state.request_id},
    )
    raise ValueError("This is an intentional error to demonstrate logging.")
