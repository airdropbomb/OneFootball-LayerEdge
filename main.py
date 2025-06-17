import asyncio
import logging
import random
import sys
from datetime import datetime, timezone, timedelta
from itertools import cycle
from typing import List, Optional, Dict, Any, Tuple, Set

from eth_account import Account
from pyuseragents import random as random_useragent
from eth_account.messages import encode_defunct
from loguru import logger
from curl_cffi.requests import AsyncSession, Response
from openpyxl.workbook import Workbook
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text
from rich.theme import Theme
import inquirer
from web3 import AsyncWeb3, AsyncHTTPProvider

from config import sleep, ref, max_concurrent_wallets, num_wallets

# Your GraphQL queries and other imports
from src.data import (
    query_verify,
    query_campaign,
    query_login,
    query_login_activities_panel,
    COMMON_HEADERS,
    query_user_me,
)
from src.logger import logging_setup
from src.task import (
    campaign_activities_panel_deil,
    verify_activity_deil,
    activity_quiz_detail,
    verify_activity_quiz,
)
# The twitter function needs to be adapted to accept twitter_auth_token parameter
from src.twitter import twitter
from src.utils import _make_request, create_signature, user_login

import warnings

warnings.filterwarnings("ignore", category=UserWarning, message="Curlm alread closed! quitting from process_data")

logger.add(sys.stdout, level="INFO")
logging_setup()
logging.getLogger('asyncio').setLevel(logging.CRITICAL)
if sys.platform.startswith('win'):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


# --- Data Loading ---

def _load_lines(file_path: str) -> List[str]:
    """Loads and cleans lines from a file."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return []
    except Exception as e:
        logger.error(f"Error loading file {file_path}: {e}")
        return []

# List of private keys and accounts
PRIVATE_KEYS = _load_lines("txt/private_keys.txt")
ACCOUNTS = [Account.from_key(key) for key in PRIVATE_KEYS]
PROXIES = _load_lines("txt/proxies.txt")
TWITTER_TOKENS = _load_lines("txt/twitter_tokens.txt")
PROXY_CYCLE = cycle(PROXIES) if PROXIES else None

# Set of processed addresses to prevent duplicate processing
PROCESSED_ADDRESSES: Set[str] = set(account.address for account in ACCOUNTS)

PRIVY_HEADERS = {
    'accept': 'application/json',
    'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
    'cache-control': 'no-cache',
    'content-type': 'application/json',
    'dnt': '1',
    'origin': 'https://club.onefootball.com',
    'pragma': 'no-cache',
    'priority': 'u=1, i',
    'privy-app-id': 'clphlvsh3034xjw0fvs59mrdc',
    'privy-client': 'react-auth:2.4.1',
    'referer': 'https://club.onefootball.com/',
    'sec-ch-ua': '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
}

def _get_proxy_url(proxy: Optional[str]) -> Optional[str]:
    """Formats the proxy URL if a proxy is provided."""
    return proxy if proxy else None


async def _get_working_proxy(proxies: List[str]) -> Optional[str]:
    """Checks and returns a working proxy from the list."""
    while True:
        rand_proxy = random.choice(proxies)
        web3 = AsyncWeb3(
            AsyncHTTPProvider(endpoint_uri='https://bsc-pokt.nodies.app', request_kwargs={"proxy": rand_proxy}))
        if await web3.is_connected():
            return rand_proxy
        else:
            logger.warning(f'{rand_proxy} is not working, trying another...')


# --- API Requests ---
async def siwe_accept_terms(session: AsyncSession, proxy: Optional[str], token: str) -> Dict[str, Any]:
    """Accepts the terms of use."""
    headers = {
        **PRIVY_HEADERS,
        'authorization': f'Bearer {token}',
        'user-agent': random_useragent(),
    }
    return await _make_request(
        session,
        'https://auth.privy.io/api/v1/users/me/accept_terms',
        headers=headers,
        json_data={},
        proxy=proxy,
        operation_name='siwe_accept_terms'
    )


async def verify_activity(
        session: AsyncSession, proxy: Optional[str], token: str, privy_id_token: str, activityId='14f59386-4b62-4178-9cd0-cc3a8feb1773'
) -> Dict[str, Any]:
    """Verifies an activity."""
    headers = {
        **COMMON_HEADERS,
        'authorization': f'Bearer {token}',
        'privy-id-token': privy_id_token,
        'x-apollo-operation-name': 'VerifyActivity',
    }
    json_data = {
        'operationName': 'VerifyActivity',
        'variables': {
            'data': {
                'activityId': activityId,
                'metadata': {
                    'referralCode': ref,
                },
            },
        },
        'query': query_verify,
    }
    return await _make_request(
        session,
        'https://api.deform.cc/',
        headers=headers,
        json_data=json_data,
        proxy=proxy,
        operation_name='verify_activity'
    )


async def campaign_activities(session: AsyncSession, proxy: Optional[str], token: str) -> Dict[str, Any]:
    """Retrieves campaign activity data."""
    headers = {
        **COMMON_HEADERS,
        'authorization': f'Bearer {token}',
        'x-apollo-operation-name': 'CampaignActivities',
    }
    json_data = {
        'operationName': 'CampaignActivities',
        'variables': {
            'campaignId': '30ea55e5-cf99-4f21-a577-5c304b0c61e2',
        },
        'query': query_campaign,
    }
    return await _make_request(
        session,
        'https://api.deform.cc/',
        headers=headers,
        json_data=json_data,
        proxy=proxy,
        operation_name='campaign_activities'
    )


async def campaign_activities_panel(session: AsyncSession, proxy: Optional[str]) -> Optional[str]:
    """Retrieves the campaign ID."""
    headers = {
        **COMMON_HEADERS,
        'cache-control': 'no-cache',
        'dnt': '1',
        'pragma': 'no-cache',
        'x-apollo-operation-name': 'CampaignSpotByCampaignIdAndReferralCode',
    }

    json_data = {
        'operationName': 'CampaignSpotByCampaignIdAndReferralCode',
        'variables': {
            'campaignId': '30ea55e5-cf99-4f21-a577-5c304b0c61e2',
            'referralCode': ref,
        },
        'query': query_login_activities_panel,
    }
    try:
        response: Response = await session.request(
            'POST',
            'https://api.deform.cc/',
            json=json_data,
            proxy=proxy,
            headers=headers
        )
        if response.status_code >= 400:
            logger.error(f"Error getting campaign ID - HTTP Error: {response.status_code}")
            if response.text:
                logger.error(f"Error getting campaign ID - HTTP Error Body: {await response.text()}")
            return None
        id = response.headers.get('x-amzn-RequestId')
        logger.debug(f"id: {id}")
        return id
    except Exception as e:
        logger.error(f"Error getting campaign ID: {e}")
        return None


async def user_me(session: AsyncSession, proxy: Optional[str], token: str, address: str) -> Optional[int]:
    """Retrieves the user's points."""
    headers = {
        **COMMON_HEADERS,
        'authorization': f'Bearer {token}',
        'x-apollo-operation-name': 'UserMe',
    }
    json_data = {
        'operationName': 'UserMe',
        'variables': {
            'campaignId': '30ea55e5-cf99-4f21-a577-5c304b0c61e2',
        },
        'query': query_user_me,
    }
    response = await _make_request(
        session,
        'https://api.deform.cc/',
        headers=headers,
        json_data=json_data,
        proxy=proxy,
        operation_name='user_me'
    )

    if (
            response
            and "data" in response
            and response["data"]["userMe"]
            and response["data"]["userMe"]['campaignSpot']
    ):
        points = response["data"]["userMe"]['campaignSpot']['points']
        logger.info(f"User points: {points} in {address}")
        return points
    else:
        logger.warning(f"Could not retrieve points for address {address}")
        return None


async def siwe_auth(
        account: Account,
        private_key: str,
        twitter_auth_token: Optional[str],
        full_guide: bool = True,
        wallet_number: int = 0,
        chek: bool = False
) -> Tuple[bool, Optional[int]]:
    """Performs SIWE authorization and related actions."""
    async with AsyncSession() as session:
        # 📌 1️⃣ Set up proxy
        proxy = None
        if PROXIES:
            proxy = await _get_working_proxy(PROXIES)

        logger.info(f"Processing wallet #{wallet_number}: {account.address} with {proxy or 'no proxy'}")

        # 📌 2️⃣ Retrieve campaign_id (with retries for 429 errors)
        campaign_id = await campaign_activities_panel(session, proxy)
        if not campaign_id:
            return False, None

        # 📌 3️⃣ Generate nonce for authorization
        headers_init = {
            **PRIVY_HEADERS,
            'User-Agent': random_useragent(),
            'privy-ca-id': campaign_id,
        }
        json_data_init = {'address': account.address}

        max_attempts = 3
        for attempt in range(max_attempts):
            await asyncio.sleep(sleep)
            response_init = await _make_request(
                session, 'https://auth.privy.io/api/v1/siwe/init',
                headers=headers_init, json_data=json_data_init, proxy=proxy, operation_name='siwe_init'
            )
            if 'nonce' in response_init:
                break
            elif response_init.get('status_code') == 429 and attempt < max_attempts - 1:
                wait_time = (attempt + 1) * 10  # Increase wait time (10, 20, 30 seconds)
                logger.warning(f"Rate limit hit. Retrying in {wait_time} seconds... (Attempt {attempt + 1}/{max_attempts})")
                await asyncio.sleep(wait_time)
            else:
                logger.error(f"Error in initial request: {response_init}")
                return False, None

        nonce = response_init['nonce']
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        message = (
            f"ofc.onefootball.com wants you to sign in with your Ethereum account:\n"
            f"{account.address}\n\nBy signing, you are proving you own this wallet and logging in. "
            f"This does not initiate a transaction or cost any fees.\n\n"
            f"URI: https://ofc.onefootball.com\nVersion: 1\nChain ID: 1\nNonce: {nonce}\n"
            f"Issued At: {expires_at}\nResources:\n- https://privy.io"
        )

        # 📌 4️⃣ Sign the message
        signature = await create_signature(message, private_key)

        json_data_auth = {
            'message': message,
            'signature': signature,
            'chainId': 'eip155:1',
            'walletClientType': 'okx_wallet',
            'connectorType': 'injected',
        }

        await asyncio.sleep(sleep)
        response_auth = await _make_request(
            session, 'https://auth.privy.io/api/v1/siwe/authenticate',
            headers=headers_init, json_data=json_data_auth, proxy=proxy, operation_name='siwe_authenticate'
        )

        if not response_auth or 'token' not in response_auth or 'identity_token' not in response_auth:
            logger.error(f"Authorization error: {response_auth}")
            return False, None

        logger.info(f'Account {account.address} successfully authorized!')
        token = response_auth['token']
        token_ref = response_auth['refresh_token']
        privy_id_token = response_auth['identity_token']

        # 📌 5️⃣ Accept terms and log in
        await asyncio.sleep(sleep)
        await siwe_accept_terms(session, proxy, token)

        await asyncio.sleep(sleep)
        user_token = await user_login(session, proxy, token)
        if not user_token:
            return False, None

        # 📌 6️⃣ Run activities (campaigns, referrals)
        await asyncio.sleep(sleep)
        await campaign_activities(session, proxy, user_token)

        await asyncio.sleep(sleep)
        await verify_activity(session, proxy, user_token, privy_id_token)
        logger.info(f'Account {account.address} passed through ref - {ref}')

        # 📌 7️⃣ Handle Twitter (if token is provided)
        if twitter_auth_token:
            logger.info(f"Attempting to connect Twitter for {account.address}")

            twitter_status = await twitter(session, proxy, token, twitter_auth_token, account.address, private_key)
            if twitter_status != 0:
                tasks = [
                    ('Twitter', '630499bc-8adb-411b-a503-d0da7de08e66'),
                    ('Follow', '4590c2de-d1ac-43b4-a403-216255ec1e6e'),
                    ('Like', '19ba588e-a6f7-4120-a8be-a29415e2ad4a')
                ]

                for task_name, task_id in tasks:
                    await asyncio.sleep(sleep)
                    await campaign_activities(session, proxy, user_token)
                    status = await verify_activity_deil(session, proxy, user_token, privy_id_token, task_id)
                    if status == 'COMPLETED':
                        logger.success(f'{task_name} completed successfully!')
                    elif status == 'ALREADY_COMPLETED':
                        logger.warning(f'{task_name} already completed.')
                    else:
                        logger.error(f'Error completing {task_name}')
        else:
            logger.warning(f"No Twitter token for {account.address}, skipping Twitter task.")

        # 📌 8️⃣ Perform additional activities (dailies, quizzes)
        if full_guide:
            await campaign_activities_panel_deil(session, proxy, user_token)
            await asyncio.sleep(sleep)
            status = await verify_activity_deil(session, proxy, user_token, privy_id_token)
            logger.success(f'Daily completed successfully!') if status == 'COMPLETED' else logger.warning(
                f'Daily already completed.')

            await activity_quiz_detail(session, proxy, user_token)
            await asyncio.sleep(sleep)
            quiz_status = await verify_activity_quiz(session, proxy, user_token, privy_id_token)
            logger.success(f'Quiz 1 completed!') if quiz_status == 'COMPLETED' else logger.warning(
                f'Quiz 1 already completed.')

            await activity_quiz_detail(session, proxy, user_token, 2)
            await asyncio.sleep(sleep)
            quiz_status = await verify_activity_quiz(session, proxy, user_token, privy_id_token, 2)
            logger.success(f'Quiz 2 completed!') if quiz_status == 'COMPLETED' else logger.warning(
                f'Quiz 2 already completed.')

            await activity_quiz_detail(session, proxy, user_token, 3)
            await asyncio.sleep(sleep)
            quiz_status = await verify_activity_quiz(session, proxy, user_token, privy_id_token, 3)
            logger.success(f'Quiz 3 completed!') if quiz_status == 'COMPLETED' else logger.warning(
                f'Quiz 3 already completed.')

            await activity_quiz_detail(session, proxy, user_token, 4)
            await asyncio.sleep(sleep)
            quiz_status = await verify_activity_quiz(session, proxy, user_token, privy_id_token, 4)
            logger.success(f'Quiz 4 completed!') if quiz_status == 'COMPLETED' else logger.warning(
                f'Quiz 4 already completed.')
        # 📌 9️⃣ Complete daily checks
        if not full_guide and not chek:
            await campaign_activities_panel_deil(session, proxy, user_token)
            await asyncio.sleep(sleep)
            status = await verify_activity_deil(session, proxy, user_token, privy_id_token)
            logger.success(f'Daily completed successfully!') if status == 'COMPLETED' else logger.warning(
                f'Daily already completed.')

        # 📌 🔟 Retrieve points and complete
        points = await user_me(session, proxy, user_token, account.address)
        return True, points


async def process_account(
        account: Account,
        private_key: str,
        twitter_auth_token: Optional[str],
        full_guide: bool,
        wallet_number: int,
        chek: bool,
) -> Tuple[str, str, Optional[int]]:
    """Processes a single account and returns report data."""
    success, points = await siwe_auth(
        account,
        private_key,
        twitter_auth_token=twitter_auth_token,
        full_guide=full_guide,
        wallet_number=wallet_number,
        chek=chek
    )
    if success:
        logger.success(f"Account {account.address}: Success")
    else:
        logger.error(f"Account {account.address}: Error")
    return private_key, account.address, points


# --- New function for processing with semaphore ---
semaphore = asyncio.Semaphore(max_concurrent_wallets)


async def process_account_with_semaphore(
        account: Account,
        private_key: str,
        i: int,
        full_guide: bool,
        chek: bool
) -> Tuple[str, str, Optional[int]]:
    async with semaphore:
        # Retrieve Twitter token if available for this index
        twitter_auth_token = TWITTER_TOKENS[i] if i < len(TWITTER_TOKENS) else None
        return await process_account(
            account,
            private_key,
            twitter_auth_token,
            full_guide,
            i + 1,
            chek,
        )


async def run_referral():
    """Runs the referral process with automatic account creation, avoiding duplicates with random delays."""
    if not PROXIES:
        logger.warning("No proxies, running without proxies.")

    try:
        num_accounts = int(input("Enter the number of accounts to create: ").strip())
        if num_accounts <= 0:
            logger.error("Number of accounts must be positive, exiting.")
            return
    except ValueError:
        logger.error("Invalid number of accounts, exiting.")
        return

    successful_count = 0
    failed_count = 0
    global PROCESSED_ADDRESSES
    start_time = datetime.now(timezone.utc)

    for i in range(num_accounts):
        account = Account.create()
        private_key = account.key.hex()
        with open("txt/private_keys.txt", "a", encoding="utf-8") as f:
            f.write(f"{private_key}\n")
        logger.info(f"Created wallet #{i+1}: {account.address[:6]}...{account.address[-4:]}")

        # Check if account was already processed
        if account.address not in PROCESSED_ADDRESSES:
            _, address, points = await process_account_with_semaphore(
                account,
                private_key,
                i + len(ACCOUNTS),
                full_guide=True,
                chek=False
            )
            PROCESSED_ADDRESSES.add(account.address)
            if points is not None:
                successful_count += 1
            else:
                failed_count += 1
        else:
            logger.warning(f"Wallet {account.address[:6)}...{account.address[-4:]} already processed, skipping.")
            continue

        # Increased random delay between accounts (5-30 seconds)
        await asyncio.sleep(random.uniform(5,30))
        logger.info(f"Progress after wallet #{i+1}: {successful_count} successful, {failed_count} failed")

    end_time = datetime.now(timezone.utc)
    total_time = end_time - start_time
    logger.success(f"Referral process completed! Final Progress: {successful_count} successful, {failed_count} failed. Total time: {total_time:.2f} seconds")

async def run_daily_only():
    """Runs only daily tasks with parallelism limits."""
    if not async ACCOUNTS or not PRIVATE_KEYS:
        logger.error("No private keys found for processing.")
        return

    if not PROXIES:
        logger.warning("No proxies, running without proxies.")

    async with AsyncSession() as session:
        tasks = [
            process_account_with_semaphore(
                account,
                private_key,
                i,
                full_guide=False
                chek=False
            )
            for i, (account, private_key) in enumerate(zip(ACCOUNTS, PRIVATE_KEYS))
        ]
        await asyncio.gather(*tasks)


async def run_checker():
    """Runs the checker (point retrieval) with parallelism limit, without performing Twitter or other activities."""
    if not ACCOUNTS or not PRIVATE_KEYS:
        logger.error("No private keys found for processing.")
        return

    if not PROXIES:
        logger.warning("No proxies, running without proxies.")

    async with AsyncSession() as session:
        tasks = [
            process_account_with_semaphore(
                account,
                private_key,
                i,
                full_guide=False,
                check=True
            )
            for i, (account, private_key) in enumerate(zip(ACCOUNTS, PRIVATE_KEYS))
        ]
        results = await asyncio.gather(*tasks)

    wb = Workbook()
    ws = wb.active
    ws.append(["Private Key", "Address", "Points"])  # Headers
    for row in results:
        ws.append(row)

    wb.save("account_results.xlsx")
    logger.success("Results saved to account_results.xlsx")


def main_menu(console: Console) -> str:
    """Displays the main menu and returns user choice."""
    questions = [
        inquirer.List(
            'action',
            message="What do you want to do?",
            choices=['Run Referral', 'Run Daily Tasks', 'Run Checker', 'Exit'],
            carousel=True
        ),
    ]
    answers = inquirer.prompt(questions)
    return answers['action']


async def main():
    """Main function to run the program."""
    console = Console(theme=Theme({
        "prompt": "bold cyan",
        "info": "bold green",
        "error": "bold red",
        "warning": "bold yellow",
        "success": "bold green",
        "title": "bold magenta",
        "description": "bold blue",
        "selected": "bold white on #666666",
        "unselected": "white"
    }))

    console.print(Panel(
        Text("OFC AUTO\nWelcome to the Onefootball Campaign Automation!", justify="center", style="title"),
        title="[bold cyan]Main Menu[/bold cyan]",
        subtitle="Automate your tasks with ease and style",
        border_style="bold magenta",
        padding=(1, 2)
    ))

    console.print(Panel(
        Text(
            "[1] Run Referral - Includes all steps of the campaign with referral process\n"
            "[2] Run Daily Tasks - Focus only on daily campaign updates\n"
            "[3] Run Checker - Check all account points\n"
            "[exit] Quit the program",
            style="description",
            justify="left"
        ),
        title="[bold cyan]Available Actions[/bold cyan]",
        border_style="bold blue",
        padding=(1, 2)
    ))

    selected_action = main_menu(console)

    if selected_action == "Run Referral":
        console.print(Panel(
            Text("Starting Referral...", justify="center", style="info"),
            border_style="green",
            padding=(1, 2)
        ))
        with Progress(
            SpinnerColumn(style="info"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Running referral...", total=100)
            for _ in range(100):
                await asyncio.sleep(0.05)
                progress.update(task, advance=1)
        await run_referral()
        console.print("[success]Referral completed![/success]")

    elif selected_action == "Run Daily Tasks":
        console.print(Panel(
            Text("Starting Daily Tasks...", justify="center", style="info"),
            border_style="blue",
            padding=(1, 2)
        ))
        await run_daily_only()
        console.print("[success]Daily tasks completed![/success]")

    elif selected_action == "Run Checker":
        console.print(Panel(
            Text("Starting Checker...", justify="center", style="info"),
            border_style="cyan",
            padding=(1, 2)
        ))
        await run_checker()
        console.print("[success]Checker completed![/success]")

    elif selected_action == "Exit":
        console.print(Panel(
            Text("Exiting the program. Goodbye!", justify="center", style="warning"),
            border_style="red",
            padding=(1, 2)
        ))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.warning("Process interrupted by user. Exiting gracefully...")
        sys.exit(0)
