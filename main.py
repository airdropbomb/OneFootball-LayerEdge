import asyncio
import logging
import sys
from datetime import datetime, timezone, timedelta
from itertools import cycle
from typing import List, Optional, Dict, Any

from eth_account import Account
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
from config import sleep, ref, max_concurrent_wallets
from src.data import query_verify, query_campaign, query_login, query_login_activities_panel, COMMON_HEADERS, \
    query_user_me
from src.logger import logging_setup
from src.task import campaign_activities_panel_deil, verify_activity_deil, activity_quiz_detail, verify_activity_quiz
from src.utils import _make_request
import warnings

warnings.filterwarnings("ignore", category=UserWarning, message="Curlm alread closed! quitting from process_data")
logger.add(sys.stdout, level="INFO")
logging_setup()
logging.getLogger('asyncio').setLevel(logging.CRITICAL)
if sys.platform.startswith('win'):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


# --- Загрузка данных ---

def _load_lines(file_path: str) -> List[str]:
    """Загружает и очищает строки из файла."""
    try:
        with open(file_path, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        logger.error(f"Файл не найден: {file_path}")
        return []
    except Exception as e:
        logger.error(f"Ошибка загрузки файла {file_path}: {e}")
        return []


PRIVATE_KEYS = _load_lines("private_keys.txt")
PROXIES = _load_lines("proxies.txt")
ACCOUNTS = [Account.from_key(key) for key in PRIVATE_KEYS]
PROXY_CYCLE = cycle(PROXIES) if PROXIES else None

PRIVY_HEADERS = {
    **COMMON_HEADERS,
    'privy-app-id': 'clphlvsh3034xjw0fvs59mrdc',
    'privy-client': 'react-auth:1.80.0-beta-20240821191745',
}


# --- Утилиты ---

async def create_signature(text: str, private_key: str) -> str:
    """Создает подпись для текста с использованием приватного ключа."""
    encoded_message = encode_defunct(text=text)
    signature = Account.sign_message(encoded_message, private_key=private_key)
    return f'0x{signature.signature.hex()}'


def _get_proxy_url(proxy: Optional[str]) -> Optional[str]:
    """Формирует URL прокси, если прокси предоставлен."""
    return proxy if proxy else None


async def _check_proxy(proxy: str) -> bool:
    """Проверяет работоспособность прокси."""
    async with AsyncSession() as session:
        try:
            response = await session.get("https://www.google.com", proxy=proxy,
                                         timeout=5)  # Измените URL на более надежный
            return response.status_code == 200
        except Exception:
            return False


async def _get_working_proxy(proxy_cycle) -> Optional[str]:
    """Получает рабочий прокси, перебирая список, и возвращает None если не находит."""
    if not PROXIES:
        return None

    for proxy in proxy_cycle:
        if await _check_proxy(proxy):
            return proxy
        else:
            logger.warning(f"Прокси не работает: {proxy}")
    logger.error("Нет рабочих прокси!")
    return None


# --- API-запросы ---

async def siwe_accept_terms(session: AsyncSession, proxy: Optional[str], token: str) -> Dict[str, Any]:
    """Принимает условия использования."""
    headers = {
        **PRIVY_HEADERS,
        'authorization': f'Bearer {token}',
    }
    return await _make_request(session, 'https://auth.privy.io/api/v1/users/me/accept_terms', headers=headers,
                               json_data={}, proxy=proxy, operation_name='siwe_accept_terms')


async def verify_activity(
        session: AsyncSession, proxy: Optional[str], token: str, privy_id_token: str
) -> Dict[str, Any]:
    """Верифицирует активность."""
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
                'activityId': '14f59386-4b62-4178-9cd0-cc3a8feb1773',
                'metadata': {
                    'referralCode': ref,
                },
            },
        },
        'query': query_verify,
    }
    return await _make_request(session, 'https://api.deform.cc/', headers=headers, json_data=json_data, proxy=proxy,
                               operation_name='verify_activity')


async def campaign_activities(session: AsyncSession, proxy: Optional[str], token: str) -> Dict[str, Any]:
    """Получает данные об активностях кампании."""
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
    return await _make_request(session, 'https://api.deform.cc/', headers=headers, json_data=json_data, proxy=proxy,
                               operation_name='campaign_activities')


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
    response = await _make_request(session, 'https://api.deform.cc/', headers=headers, json_data=json_data, proxy=proxy,
                                   operation_name='user_login')
    if response and "data" in response and 'userLogin' in response["data"]:
        token = response["data"]["userLogin"]
        logger.debug(f"User Login Token: {token}")
        return token
    return None


async def campaign_activities_panel(session: AsyncSession, proxy: Optional[str]) -> Optional[str]:
    """Получает ID кампании."""
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
        response: Response = await session.request('POST', 'https://api.deform.cc/', json=json_data, proxy=proxy,
                                                   headers=headers)
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
    response = await _make_request(session, 'https://api.deform.cc/', headers=headers, json_data=json_data, proxy=proxy,
                                   operation_name='user_me')

    if response and "data" in response and response["data"]["userMe"] and response["data"]["userMe"]['campaignSpot']:
        points = response["data"]["userMe"]['campaignSpot']['points']
        logger.info(f"User points: {points} in {address}")
        return points
    else:
        logger.warning(f"Could not retrieve points for address {address}")
        return None


async def siwe_auth(session: AsyncSession, account: Account, private_key: str, proxy: Optional[str],
                    full_guide: bool = True, wallet_number: int = 0, chek: bool = False) -> tuple[bool, Optional[int]]:
    """Выполняет авторизацию SIWE и связанные действия."""
    logger.info(f"Обработка кошелька #{wallet_number}: {account.address} с {proxy or 'без прокси'}")
    campaign_id = await campaign_activities_panel(session, proxy)
    if not campaign_id:
        return False, None

    headers_init = {
        **PRIVY_HEADERS,
        'privy-ca-id': campaign_id,
    }
    json_data_init = {'address': account.address}

    await asyncio.sleep(sleep)
    response_init = await _make_request(
        session,
        'https://auth.privy.io/api/v1/siwe/init',
        headers=headers_init,
        json_data=json_data_init,
        proxy=proxy,
        operation_name='siwe_init',
    )

    if 'nonce' not in response_init:
        logger.error(f"Ошибка в первом запросе")
        return False, None
    await asyncio.sleep(sleep)
    nonce = response_init['nonce']
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    message = (
        f"ofc.onefootball.com wants you to sign in with your Ethereum account:\n"
        f"{account.address}\n\nBy signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.\n\n"
        f"URI: https://ofc.onefootball.com\nVersion: 1\nChain ID: 1\nNonce: {nonce}\n"
        f"Issued At: {expires_at}\nResources:\n- https://privy.io"
    )

    signature = await create_signature(message, private_key)

    json_data_auth = {
        'message': message,
        'signature': signature,
        'chainId': 'eip155:1',
        'walletClientType': 'rabby_wallet',
        'connectorType': 'injected',
    }
    await asyncio.sleep(sleep)
    response_auth = await _make_request(
        session,
        'https://auth.privy.io/api/v1/siwe/authenticate',
        headers=headers_init,
        json_data=json_data_auth,
        proxy=proxy,
        operation_name='siwe_authenticate',
    )

    if not response_auth or 'token' not in response_auth or 'identity_token' not in response_auth:
        logger.error(f"Ошибка в авторизации: {response_auth}")
        return False, None
    logger.info(f'Аккаунт {account.address} зарегистрирован!')

    token = response_auth['token']
    privy_id_token = response_auth['identity_token']

    await asyncio.sleep(sleep)
    await siwe_accept_terms(session, proxy, token)
    await asyncio.sleep(sleep)
    user_token = await user_login(session, proxy, token)
    if not user_token: return False, None
    await asyncio.sleep(sleep)
    await campaign_activities(session, proxy, user_token)
    await asyncio.sleep(sleep)
    await verify_activity(session, proxy, user_token, privy_id_token)
    logger.info(f'Аккаунт {account.address} прошел через реф - {ref}')
    await asyncio.sleep(sleep)

    if full_guide:
        await campaign_activities_panel_deil(session, proxy, user_token)
        await asyncio.sleep(sleep)
        status = await verify_activity_deil(session, proxy, user_token, privy_id_token)
        if status == 'COMPLETED':
            logger.success(f'Дейлик выполнен успешно!.')
        elif status == 'ALREADY_COMPLETED':
            logger.warning(f'Дейлик уже выполнен, пропускаю...')
        else:
            logger.error(f'Ошибка при выполнении дейлика')
        await asyncio.sleep(sleep)

        await activity_quiz_detail(session, proxy, user_token)
        await asyncio.sleep(sleep)
        quiz_status = await verify_activity_quiz(session, proxy, user_token, privy_id_token)
        if quiz_status == 'COMPLETED':
            logger.success(f'Квиз выполнен! {account.address}')
        elif status == 'ALREADY_COMPLETED':
            logger.warning(f'Квиз уже выполнен, пропускаю...')
        else:
            logger.error(f'Квиз не выполнен {account.address}')
        await asyncio.sleep(sleep)

    if full_guide == False and chek == False:
        await campaign_activities_panel_deil(session, proxy, user_token)
        await asyncio.sleep(sleep)
        status = await verify_activity_deil(session, proxy, user_token, privy_id_token)
        if status == 'COMPLETED':
            logger.success(f'Дейлик выполнен успешно!.')
        elif status == 'ALREADY_COMPLETED':
            logger.warning(f'Дейлик уже выполнен, пропускаю.')
        else:
            logger.error(f'Ошибка при выполнении дейлика.')
        await asyncio.sleep(sleep)
    points = await user_me(session, proxy, user_token, account.address)

    return True, points


async def process_account(account: Account, private_key: str, proxy: Optional[str], full_guide: bool,
                          wallet_number: int, chek: bool, session) -> tuple[str, str, Optional[int]]:
    """Обрабатывает один аккаунт и возвращает данные для отчета."""
    success, points = await siwe_auth(session, account, private_key, proxy, full_guide, wallet_number, chek)
    if success:
        logger.success(f"Account {account.address}: Success")
    else:
        logger.error(f"Account {account.address}: Error")
    return private_key, account.address, points

# --- Новая функция для обработки с семафором ---
semaphore = asyncio.Semaphore(max_concurrent_wallets)


async def process_account_with_semaphore(session, account, private_key, proxy, i, full_guide, chek):
    async with semaphore:
        return await process_account(account, private_key, proxy, full_guide, i + 1, chek, session)


async def run_full_guide():
    """Запускает полную цепочку действий с ограничением параллелизма."""
    if not ACCOUNTS or not PRIVATE_KEYS:
        logger.error("Нет приватных ключей для обработки.")
        return

    if not PROXIES:
        logger.warning("Нет прокси, будет выполнятся без прокси.")

    proxy_cycle = cycle(PROXIES) if PROXIES else None

    async with AsyncSession() as session:
        tasks = [process_account_with_semaphore(session, account, private_key, await _get_working_proxy(proxy_cycle), i,
                                                True, False)
                 for i, (account, private_key) in enumerate(zip(ACCOUNTS, PRIVATE_KEYS))]
        all_results = await asyncio.gather(*tasks)


async def run_daily_only():
    """Запускает только дейлик с ограничением параллелизма."""
    if not ACCOUNTS or not PRIVATE_KEYS:
        logger.error("Нет приватных ключей для обработки.")
        return

    if not PROXIES:
        logger.warning("Нет прокси, будет выполнятся без прокси.")
    proxy_cycle = cycle(PROXIES) if PROXIES else None
    async with AsyncSession() as session:
        tasks = [process_account_with_semaphore(session, account, private_key, await _get_working_proxy(proxy_cycle), i,
                                                False, False)
                 for i, (account, private_key) in enumerate(zip(ACCOUNTS, PRIVATE_KEYS))]
        all_results = await asyncio.gather(*tasks)


async def run_chek():
    """Запускает чекер с ограничением параллелизма."""
    if not ACCOUNTS or not PRIVATE_KEYS:
        logger.error("Нет приватных ключей для обработки.")
        return

    if not PROXIES:
        logger.warning("Нет прокси, будет выполнятся без прокси.")
    proxy_cycle = cycle(PROXIES) if PROXIES else None
    async with AsyncSession() as session:
        tasks = [process_account_with_semaphore(session, account, private_key, await _get_working_proxy(proxy_cycle), i,
                                                False, True)
                 for i, (account, private_key) in enumerate(zip(ACCOUNTS, PRIVATE_KEYS))]
        results = await asyncio.gather(*tasks)

    wb = Workbook()
    ws = wb.active
    ws.append(["Private Key", "Address", "Points"])  # Заголовки
    for row in results:
        ws.append(row)

    wb.save("account_results.xlsx")
    logger.success("Results saved to account_results.xlsx")


def main_menu(console):
    questions = [
        inquirer.List('action',
                      message="What do you want to do?",
                      choices=['Run the Full Guide', 'Run Daily Tasks', 'Run Checker', 'Exit'],
                      carousel=True
                      ),
    ]
    answers = inquirer.prompt(questions)
    return answers['action']


async def main():
    """Главная функция для запуска программы."""
    console = Console(theme=Theme({
        "prompt": "bold cyan",
        "info": "bold green",
        "error": "bold red",
        "warning": "bold yellow",
        "success": "bold green",
        "title": "bold magenta",
        "description": "bold blue",
        "selected": "bold white on #666666",  # стиль для выбранного пункта
        "unselected": "white"  # стиль для невыбранных пунктов
    }))

    # Декоративная панель заголовка
    console.print(Panel(
        Text("OFC AUTO\nWelcome to the Onefootball Campaign Automation!", justify="center", style="title"),
        title="[bold cyan]Main Menu[/bold cyan]",
        subtitle="Automate your tasks with ease and style",
        border_style="bold magenta",
        padding=(1, 2)
    ))

    # Описание доступных действий
    console.print(Panel(
        Text(
            "[1] Run the Full Guide - Includes all steps of the campaign\n"
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

    if selected_action == "Run the Full Guide":
        console.print(Panel(
            Text("Starting Full Guide...", justify="center", style="info"),
            border_style="green",
            padding=(1, 2)
        ))
        with Progress(
                SpinnerColumn(style="info"),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                console=console
        ) as progress:
            task = progress.add_task("Running full guide...", total=100)
            for i in range(100):
                await asyncio.sleep(0.05)  # Симуляция процесса
                progress.update(task, advance=1)
        await run_full_guide()
        console.print("[success]Full guide completed![/success]")
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
            border_style="blue",
            padding=(1, 2)
        ))
        await run_chek()
        console.print("[success]Checker completed![/success]")
    elif selected_action == "Exit":
        console.print(Panel(
            Text("Exiting the program. Goodbye!", justify="center", style="warning"),
            border_style="red",
            padding=(1, 2)
        ))


if __name__ == "__main__":
    asyncio.run(main())