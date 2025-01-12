from typing import Optional, Dict, Any
from curl_cffi.requests import AsyncSession, Response
from src.data import COMMON_HEADERS
from loguru import logger


async def _make_request(
    session: AsyncSession,
    url: str,
    method: str = "POST",
    headers: Optional[Dict] = None,
    json_data: Optional[Dict] = None,
    proxy: Optional[str] = None,
    operation_name: Optional[str] = None,
    level: str = "debug",  # Добавлен параметр level по умолчанию debug
) -> Dict[str, Any]:
    """Выполняет HTTP-запрос с заданными параметрами используя curl_cffi."""
    headers = headers if headers else COMMON_HEADERS
    log_info = f"Request to {url}, operation: {operation_name or 'None'}"
    try:
        response: Response = await session.request(
            method,
            url,
            headers=headers,
            json=json_data,
            proxy=proxy,
        )
        if response.status_code >= 400:
            logger.error(f"{log_info} - HTTP Error: {response.status_code} Text: {response.text}")
            return {}
        response_data = response.json()
        if level == "debug":
            logger.debug(f"{log_info} Response: {response_data}")
        elif level == "info":
             logger.info(f"{log_info} Response: {response_data}")
        return response_data
    except Exception as e:
        logger.error(f"{log_info} Error: {e}")
        return {}