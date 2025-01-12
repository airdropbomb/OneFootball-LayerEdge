# task.py
from typing import Optional

from src.data import query_deil, query_verify_deil, query_quiz, query_quiz_verify, COMMON_HEADERS
from src.utils import _make_request
from curl_cffi.requests import AsyncSession
from loguru import logger


async def campaign_activities_panel_deil(session: AsyncSession, proxy: Optional[str], token: str) -> None:
    """Получает данные для панели активностей кампании (дейлик)."""
    headers = {
        **COMMON_HEADERS,
        'authorization': f'Bearer {token}',
        'x-apollo-operation-name': 'CampaignActivitiesPanel',
    }

    json_data = {
        'operationName': 'CampaignActivitiesPanel',
        'variables': {
            'campaignId': '30ea55e5-cf99-4f21-a577-5c304b0c61e2',
            'isTrusted': True,
        },
        'query': query_deil,
    }

    await _make_request(
        session,
        'https://api.deform.cc/',
        headers=headers,
        json_data=json_data,
        proxy=proxy,
        operation_name='campaign_activities_panel_deil'
    )


async def verify_activity_deil(session: AsyncSession, proxy: Optional[str], token: str, token_id: str) -> str:
    """
    Верифицирует активность (дейлик).
    Возвращает статус выполнения:
    - 'COMPLETED' - дейлик выполнен успешно.
    - 'ALREADY_COMPLETED' - дейлик уже был выполнен ранее.
    - 'ERROR' - ошибка в запросе или неизвестный статус.
    """
    headers = {
        **COMMON_HEADERS,
        'authorization': f'Bearer {token}',
        'privy-id-token': token_id,
        'x-apollo-operation-name': 'VerifyActivity',
    }

    json_data = {
        'operationName': 'VerifyActivity',
        'variables': {
            'data': {
                'activityId': 'c326c0bb-0f42-4ab7-8c5e-4a648259b807',
            },
        },
        'query': query_verify_deil,
    }

    response_data = await _make_request(
        session,
        'https://api.deform.cc/',
        headers=headers,
        json_data=json_data,
        proxy=proxy,
        operation_name='verify_activity_deil'
    )

    # Проверка ответа
    if isinstance(response_data, dict):
        if 'errors' in response_data and response_data['errors']:
            logger.warning("API вернуло ошибку: дейлик уже выполнен или другая ошибка.")
            return 'ALREADY_COMPLETED'
        if 'data' in response_data and 'verifyActivity' in response_data['data']:
            record = response_data['data']['verifyActivity'].get('record', {})
            status = record.get('status')
            if status == 'COMPLETED':
                return 'COMPLETED'

    # Если ничего не подошло, возвращаем ошибку
    logger.error("Не удалось проверить статус дейлика, неизвестный ответ API.")
    return 'ERROR'



async def activity_quiz_detail(session: AsyncSession, proxy: Optional[str], token: str) -> None:
    """Получает детали квиза."""
    headers = {
        **COMMON_HEADERS,
        'authorization': f'Bearer {token}',
        'x-apollo-operation-name': 'ActivityQuizDetail',
    }
    json_data = {
        'operationName': 'ActivityQuizDetail',
        'variables': {
            'activityId': 'd05d17cb-9ecd-404e-850e-f7d92b895bb4',
        },
        'query': query_quiz,
    }

    await _make_request(
        session,
        'https://api.deform.cc/',
        headers=headers,
        json_data=json_data,
        proxy=proxy,
        operation_name='activity_quiz_detail'
    )


async def verify_activity_quiz(session: AsyncSession, proxy: Optional[str], token: str, token_id: str) -> str:
    """Верифицирует активность (квиз)."""
    headers = {
        **COMMON_HEADERS,
        'authorization': f'Bearer {token}',
        'privy-id-token': token_id,
        'x-apollo-operation-name': 'VerifyActivity',
    }

    json_data = {
        'operationName': 'VerifyActivity',
        'variables': {
            'data': {
                'activityId': 'd05d17cb-9ecd-404e-850e-f7d92b895bb4',
                'metadata': {
                    'responses': [
                        {
                            'questionId': 'q1',
                            'answers': [
                                {
                                    'id': 'a',
                                    'text': '',
                                },
                            ],
                        },
                        {
                            'questionId': 'q2',
                            'answers': [
                                {
                                    'id': 'd',
                                    'text': '',
                                },
                            ],
                        },
                        {
                            'questionId': 'q3',
                            'answers': [
                                {
                                    'id': 'd',
                                    'text': '',
                                },
                            ],
                        },
                    ],
                },
            },
        },
        'query': query_quiz_verify,
    }

    response_data = await _make_request(
        session,
        'https://api.deform.cc/',
        headers=headers,
        json_data=json_data,
        proxy=proxy,
        operation_name='verify_activity_quiz'
    )

    # Проверка ответа
    if isinstance(response_data, dict):
        if 'errors' in response_data and response_data['errors']:
            logger.warning("API вернуло ошибку: квиз уже выполнен или другая ошибка.")
            return 'ALREADY_COMPLETED'
        if 'data' in response_data and 'verifyActivity' in response_data['data']:
            record = response_data['data']['verifyActivity'].get('record', {})
            status = record.get('status')
            if status == 'COMPLETED':
                return 'COMPLETED'

    # Если ничего не подошло, возвращаем ошибку
    logger.error("Не удалось проверить статус квиза, неизвестный ответ API.")
    return 'ERROR'
