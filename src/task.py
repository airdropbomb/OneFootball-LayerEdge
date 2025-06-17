from typing import Optional

from src.data import (
    query_deil,
    query_verify_deil,
    query_quiz,
    query_quiz_verify,
    COMMON_HEADERS,
    json_data_qz_1,
    json_data_qz_2,
    json_data_qz1,
    json_data_qz2,
    json_data_3,
    json_data_qz4,
    json_data_4,
    json_data_qz3,
)
from src.utils import _make_request
from curl_cffi.requests import AsyncSession
from loguru import logger


async def campaign_activities_panel_deil(session: AsyncSession, proxy: Optional[str], token: str) -> None:
    """Retrieves data for the campaign activities panel (daily tasks)."""
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


async def verify_activity_deil(
    session: AsyncSession,
    proxy: Optional[str],
    token: str,
    token_id: str,
    activityId='c326c0bb-0f42-4ab7-8c5e-4a648259b807'
) -> str:
    """
    Verifies a daily activity.
    Returns the completion status:
    - 'COMPLETED' - Daily task completed successfully.
    - 'ALREADY_COMPLETED' - Daily task was already completed previously.
    - 'ERROR' - Error in the request or unknown status.
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
                'activityId': activityId,
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

    # Check the response
    if isinstance(response_data, dict):
        if 'errors' in response_data and response_data['errors']:
            return 'ALREADY_COMPLETED'
        if 'data' in response_data and 'verifyActivity' in response_data['data']:
            record = response_data['data']['verifyActivity'].get('record', {})
            status = record.get('status')
            if status == 'COMPLETED':
                return 'COMPLETED'

    logger.error("Failed to verify status, unknown API response.")
    return 'ERROR'


async def activity_quiz_detail(session: AsyncSession, proxy: Optional[str], token: str, num=None) -> None:
    """Retrieves quiz details."""
    headers = {
        **COMMON_HEADERS,
        'authorization': f'Bearer {token}',
        'x-apollo-operation-name': 'ActivityQuizDetail',
    }
    if num == 2:
        json_data = json_data_qz2
    elif num == 3:
        json_data = json_data_qz3
    elif num == 4:
        json_data = json_data_qz4
    else:
        json_data = json_data_qz1

    await _make_request(
        session,
        'https://api.deform.cc/',
        headers=headers,
        json_data=json_data,
        proxy=proxy,
        operation_name='activity_quiz_detail'
    )


async def verify_activity_quiz(
    session: AsyncSession, proxy: Optional[str], token: str, token_id: str, num=None
) -> str:
    """Verifies a quiz activity."""
    if num == 2:
        json_data = json_data_qz_2
    elif num == 3:
        json_data = json_data_3
    elif num == 4:
        json_data = json_data_4
    else:
        json_data = json_data_qz_1

    headers = {
        **COMMON_HEADERS,
        'authorization': f'Bearer {token}',
        'privy-id-token': token_id,
        'x-apollo-operation-name': 'VerifyActivity',
    }

    response_data = await _make_request(
        session,
        'https://api.deform.cc/',
        headers=headers,
        json_data=json_data,
        proxy=proxy,
        operation_name='verify_activity_quiz'
    )

    # Check the response
    if isinstance(response_data, dict):
        if 'errors' in response_data and response_data['errors']:
            logger.warning("API returned an error: quiz already completed or other error.")
            return 'ALREADY_COMPLETED'
        if 'data' in response_data and 'verifyActivity' in response_data['data']:
            record = response_data['data']['verifyActivity'].get('record', {})
            status = record.get('status')
            if status == 'COMPLETED':
                return 'COMPLETED'

    # Return error if no valid response
    logger.error("Failed to verify quiz status, unknown API response.")
    return 'ERROR'
