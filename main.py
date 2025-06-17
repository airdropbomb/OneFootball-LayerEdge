import asyncio
import sys
import logging
import random
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any, Tuple
from itertools import cycle

from eth_account import Account
from pyuseragents import random as random_useragent
from loguru import logger
from curl_cffi.requests import AsyncSession
from web3 import AsyncWeb3, AsyncHTTPProvider

from config import sleep, ref, max_concurrent_wallets, sleep_wallets
from src.data import query_verify, query_login_activities_panel, COMMON_HEADERS, query_user_me
from src.logger import logging_setup
from src.task import campaign_activities_panel_deil, verify_activity_deil
from src.utils import _make_request, create_signature, user_login

# Logger setup
logger.add(sys.stdout, level="INFO")
logging_setup()
logging.getLogger('asyncio').setLevel(logging.CRITICAL)
if sys.platform.startswith('win'):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# Load data from files
def _load_lines(file_path: str) -> List[str]:
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return []
    except Exception as e:
        logger.error(f"Error loading file {file_path}: {e}")
        return []

PRIVATE_KEYS = _load_lines("txt/private_keys.txt")
PROXIES = _load_lines("txt/proxies.txt")
ACCOUNTS = [Account.from_key(key) for key in PRIVATE_KEYS]
PROXY_CYCLE = cycle(PROXIES) if PROXIES else None

PRIVY_HEADERS = {
    'accept': 'application/json',
    'content-type': 'application/json',
    'origin': 'https://club.onefootball.com',
    'privy-app-id': 'clphlvsh3034xjw0fvs59mrdc',
    'privy-client': 'react-auth:2.4.1',
    'referer': 'https://club.onefootball.com/',
    'user-agent': random_useragent(),
}

async def _get_working_proxy(proxies: List[str]) -> Optional[str]:
    while True:
        rand_proxy = random.choice(proxies)
        web3 = AsyncWeb3(AsyncHTTPProvider(endpoint_uri='https://bsc-pokt.nodies.app', request_kwargs={"proxy": rand_proxy}))
        if await web3.is_connected():
            return rand_proxy
        else:
            logger.warning(f'{rand_proxy} not working, trying another...')

async def siwe_accept_terms(session: AsyncSession, proxy: Optional[str], token: str) -> Dict[str, Any]:
    headers = {**PRIVY_HEADERS, 'authorization': f'Bearer {token}', 'user-agent': random_useragent()}
    return await _make_request(
        session, 'https://auth.privy.io/api/v1/users/me/accept_terms',
        headers=headers, json_data={}, proxy=proxy, operation_name='siwe_accept_terms'
    )

async def verify_activity(
        session: AsyncSession, proxy: Optional[str], token: str, privy_id_token: str,
        activityId='14f59386-4b62-4178-9cd0-cc3a8feb1773'
) -> Dict[str, Any]:
    headers = {
        **COMMON_HEADERS, 'authorization': f'Bearer {token}', 'privy-id-token': privy_id_token,
        'x-apollo-operation-name': 'VerifyActivity'
    }
    json_data = {
        'operationName': 'VerifyActivity',
        'variables': {'data': {'activityId': activityId, 'metadata': {'referralCode': ref}}},
        'query': query_verify
    }
    return await _make_request(
        session, 'https://api.deform.cc/', headers=headers, json_data=json_data, proxy=proxy, operation_name='verify_activity'
    )

async def campaign_activities_panel(session: AsyncSession, proxy: Optional[str]) -> Optional[str]:
    headers = {**COMMON_HEADERS, 'x-apollo-operation-name': 'CampaignSpotByCampaignIdAndReferralCode'}
    json_data = {
        'operationName': 'CampaignSpotByCampaignIdAndReferralCode',
        'variables': {'campaignId': '30ea55e5-cf99-4f21-a577-5c304b0c61e2', 'referralCode': ref},
        'query': query_login_activities_panel
    }
    try:
        response = await session.request('POST', 'https://api.deform.cc/', json=json_data, proxy=proxy, headers=headers)
        if response.status_code >= 400:
            logger.error(f"Error getting campaign ID - HTTP Error: {response.status_code}")
            return None
        return response.headers.get('x-amzn-RequestId')
    except Exception as e:
        logger.error(f"Error getting campaign ID: {e}")
        return None

async def user_me(session: AsyncSession, proxy: Optional[str], token: str, address: str) -> Optional[int]:
    headers = {**COMMON_HEADERS, 'authorization': f'Bearer {token}', 'x-apollo-operation-name': 'UserMe'}
    json_data = {
        'operationName': 'UserMe',
        'variables': {'campaignId': '30ea55e5-cf99-4f21-a577-5c304b0c61e2'},
        'query': query_user_me
    }
    response = await _make_request(
        session, 'https://api.deform.cc/', headers=headers, json_data=json_data, proxy=proxy, operation_name='user_me'
    )
    if response and "data" in response and response["data"]["userMe"] and response["data"]["userMe"]['campaignSpot']:
        points = response["data"]["userMe"]['campaignSpot']['points']
        logger.info(f"User points: {points} in {address}")
        return points
    logger.warning(f"Could not retrieve points for address {address}")
    return None

async def siwe_auth(account: Account, private_key: str, wallet_number: int) -> Tuple[bool, Optional[int]]:
    if wallet_number % max_concurrent_wallets == 0:
        logger.info(f'Sleeping for {sleep_wallets} seconds')
        await asyncio.sleep(sleep_wallets)
    async with AsyncSession() as session:
        proxy = await _get_working_proxy(PROXIES) if PROXIES else None
        logger.info(f"Processing wallet #{wallet_number}: {account.address} with {proxy or 'no proxy'}")

        campaign_id = await campaign_activities_panel(session, proxy)
        if not campaign_id:
            return False, None

        headers_init = {**PRIVY_HEADERS, 'user-agent': random_useragent(), 'privy-ca-id': campaign_id}
        json_data_init = {'address': account.address}
        await asyncio.sleep(sleep)
        response_init = await _make_request(
            session, 'https://auth.privy.io/api/v1/siwe/init',
            headers=headers_init, json_data=json_data_init, proxy=proxy, operation_name='siwe_init'
        )
        if 'nonce' not in response_init:
            logger.error(f"Error in init request: {response_init}")
            return False, None

        await asyncio.sleep(sleep)
        nonce = response_init['nonce']
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        message = (
            f"ofc.onefootball.com wants you to sign in with your Ethereum account:\n"
            f"{account.address}\n\nBy signing, you are proving you own this wallet and logging in. "
            f"This does not initiate a transaction or cost any fees.\n\n"
            f"URI: https://ofc.onefootball.com\nVersion: 1\nChain ID: 1\nNonce: {nonce}\n"
            f"Issued At: {expires_at}\nResources:\n- https://privy.io"
        )

        signature = await create_signature(message, private_key)
        json_data_auth = {
            'message': message, 'signature': signature, 'chainId': 'eip155:1',
            'walletClientType': 'okx_wallet', 'connectorType': 'injected'
        }
        await asyncio.sleep(sleep)
        response_auth = await _make_request(
            session, 'https://auth.privy.io/api/v1/siwe/authenticate',
            headers=headers_init, json_data=json_data_auth, proxy=proxy, operation_name='siwe_authenticate'
        )
        if not response_auth or 'token' not in response_auth or 'identity_token' not in response_auth:
            logger.error(f"Error in authentication: {response_auth}")
            return False, None

        logger.info(f'Account {account.address} successfully authenticated!')
        token = response_auth['token']
        privy_id_token = response_auth['identity_token']

        await asyncio.sleep(sleep)
        await siwe_accept_terms(session, proxy, token)
        await asyncio.sleep(sleep)
        user_token = await user_login(session, proxy, token)
        if not user_token:
            return False, None

        # Auto Refer
        await asyncio.sleep(sleep)
        await verify_activity(session, proxy, user_token, privy_id_token)
        logger.info(f'Account {account.address} processed referral - {ref}')

        # Daily Check-In
        await asyncio.sleep(sleep)
        await campaign_activities_panel_deil(session, proxy, user_token)
        await asyncio.sleep(sleep)
        status = await verify_activity_deil(session, proxy, user_token, privy_id_token)
        logger.success(f'Daily check-in completed!') if status == 'COMPLETED' else logger.warning(f'Daily check-in already completed.')

        # Get Points
        points = await user_me(session, proxy, user_token, account.address)
        return True, points

async def process_account(account: Account, private_key: str, wallet_number: int) -> Tuple[str, str, Optional[int]]:
    success, points = await siwe_auth(account, private_key, wallet_number)
    if success:
        logger.success(f"Account {account.address}: Success")
    else:
        logger.error(f"Account {account.address}: Error")
    return private_key, account.address, points

semaphore = asyncio.Semaphore(max_concurrent_wallets)

async def process_account_with_semaphore(account: Account, private_key: str, i: int) -> Tuple[str, str, Optional[int]]:
    async with semaphore:
        return await process_account(account, private_key, i + 1)

async def run_daily_and_refer():
    if not ACCOUNTS or not PRIVATE_KEYS:
        logger.error("No private keys to process.")
        return
    if not PROXIES:
        logger.warning("No proxies, running without proxies.")
    tasks = [
        process_account_with_semaphore(account, private_key, i)
        for i, (account, private_key) in enumerate(zip(ACCOUNTS, PRIVATE_KEYS))
    ]
    results = await asyncio.gather(*tasks)
    
    from openpyxl import Workbook
    wb = Workbook()
    ws = wb.active
    ws.append(["Private Key", "Address", "Points"])
    for row in results:
        ws.append(row)
    wb.save("account_results.xlsx")
    logger.success("Results saved to account_results.xlsx")

if __name__ == "__main__":
    asyncio.run(run_daily_and_refer())
