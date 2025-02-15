import asyncio
from typing import Optional, Dict, Any
from curl_cffi.requests import AsyncSession, Response
from eth_account import Account
from eth_account.messages import encode_defunct

from config import retray, base_delay, backoff_factor, max_delay
from src.data import COMMON_HEADERS, query_login
from loguru import logger


async def _make_request(
    session: "AsyncSession",
    url: str,
    method: str = "POST",
    headers: Optional[Dict[str, str]] = None,
    json_data: Optional[Dict[str, Any]] = None,
    params = None,
    cookies = None,
    allow_redirects = None,
    proxy: Optional[str] = None,
    operation_name: Optional[str] = None,
    level: str = "debug",
    ret: int = retray,
    base_delay = base_delay,        # Начальная задержка перед ретраем
    backoff_factor = backoff_factor,    # Множитель экспоненциального роста
    max_delay = max_delay         # Максимальная задержка
) -> Dict[str, Any]:
    """
    Выполняет HTTP-запрос с заданными параметрами используя curl_cffi.
    Повторяет запрос в случае ошибки ret раз, используя экспоненциальную задержку.
    """
    headers = headers if headers else COMMON_HEADERS
    log_info = f"Request to {url}, operation: {operation_name or 'None'}"

    for attempt in range(1, ret + 1):
        try:

            response: "Response" = await session.request(
                method,
                url,
                params=params,
                headers=headers,
                json=json_data,
                proxy=proxy,
                allow_redirects = allow_redirects,
                cookies=cookies
            )
            if method == "GET":
                if response.status_code <= 500:
                    return response
            if response.status_code <= 400:
                response_data = response.json()
                if level == "debug":
                    logger.debug(f"{log_info} Response: {response_data}")
                elif level == "info":
                    logger.info(f"{log_info} Response: {response_data}")
                return response_data
            else:
                logger.error(
                    f"{log_info} - Attempt {attempt}/{ret} returned status {response.status_code}. "
                    f"Text: {response.text}"
                )
                if attempt < ret:
                    delay = min(base_delay * (backoff_factor ** (attempt - 1)), max_delay)
                    logger.warning(f"Retrying in {delay} seconds...")
                    await asyncio.sleep(delay)

        except Exception as e:
            logger.error(f"{log_info} - Attempt {attempt}/{ret} raised an exception: {e}")
            if attempt < ret:
                delay = min(base_delay * (backoff_factor ** (attempt - 1)), max_delay)
                logger.warning(f"Retrying in {delay} seconds...")
                await asyncio.sleep(delay)

    logger.error(f"{log_info} - All {ret} attempts failed.")
    return {}

async def create_signature(text: str, private_key: str) -> str:
    """Создает подпись для текста с использованием приватного ключа."""
    encoded_message = encode_defunct(text=text)
    signature = Account.sign_message(encoded_message, private_key=private_key)
    return f'0x{signature.signature.hex()}'

async def user_login(session: AsyncSession, proxy: Optional[str], token: str) -> Optional[str]:
    """Выполняет вход пользователя."""
    headers = {
        **COMMON_HEADERS,
        'x-apollo-operation-name': 'UserLogin',
    }
    json_data = {
        'operationName': 'UserLogin',
        'variables': {
            'data': {
                'externalAuthToken': f'{token}',
            },
        },
        'query': query_login,
    }
    response = await _make_request(
        session,
        'https://api.deform.cc/',
        headers=headers,
        json_data=json_data,
        proxy=proxy,
        operation_name='user_login'
    )
    if response and "data" in response and 'userLogin' in response["data"]:
        token = response["data"]["userLogin"]
        token_ref = response["data"]["userLogin"]

        logger.debug(f"User Login Token: {token}")
        return token
    return None