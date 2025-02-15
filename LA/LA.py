import asyncio
import aiohttp
import time
from eth_account import Account
from web3.auto import w3
from src.utils import create_signature

MAX_CONCURRENT_TASKS = 3
sleep = 1
ref = 's6vtkNva'

# Асинхронная загрузка данных из файла
async def load_lines_async(filename):
    with open(filename, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file.readlines()]

# Асинхронный запрос к API с поддержкой прокси
async def make_request(session, url, method="GET", headers=None, json_data=None, proxy=None):
    try:
        async with session.request(method, url, headers=headers, json=json_data, proxy=proxy) as response:
            return await response.json()
    except Exception as e:
        print(f"❌ Ошибка запроса {url}: {e}")
        return None

# Основной асинхронный процесс для одного кошелька
async def process_wallet(session, pk, proxy, semaphore, i):
    async with semaphore:  # Ограничение количества одновременных задач
        account = Account.from_key(pk)
        address = account.address

        headers = {
            'accept': 'application/json, text/plain, */*',
            'content-type': 'application/json',
            'origin': 'https://dashboard.layeredge.io',
            'referer': 'https://dashboard.layeredge.io/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
        }

        # print(f"🔹 Обрабатываю кошелёк: {address} (Прокси: {proxy})")

        # 1. Регистрация кошелька
        json_data = {'walletAddress': address}
        response = await make_request(session,
                                      f'https://referralapi.layeredge.io/api/referral/register-wallet/{ref}',
                                      "POST", headers, json_data, proxy)
        print(f"[{address}] Регистрация: {response}")

        await asyncio.sleep(sleep)

        # 2. Активация узла
        timestamp_ms = int(time.time() * 1000)
        message = f'Node activation request for {address} at {timestamp_ms}'
        sign = await create_signature(message, pk)

        json_data = {'sign': sign, 'timestamp': timestamp_ms}
        response = await make_request(session,
                                      f'https://referralapi.layeredge.io/api/light-node/node-action/{address}/start',
                                      "POST", headers, json_data, proxy)
        print(f"[{address}] Активация узла: {response}")

        await asyncio.sleep(sleep)

        # 3. Проверяем статус узла
        response = await make_request(session,
                                      f'https://referralapi.layeredge.io/api/light-node/node-status/{address}',
                                      "GET", headers, proxy=proxy)
        print(f"[{address}] Статус узла: {response}")

        await asyncio.sleep(sleep)

        # 4. Запрос на получение очков
        timestamp_ms = int(time.time() * 1000)
        message = f'I am claiming my daily node point for {address} at {timestamp_ms}'
        sign = await create_signature(message, pk)

        json_data = {'walletAddress': address, 'timestamp': timestamp_ms, 'sign': sign}
        response = await make_request(session,
                                      'https://referralapi.layeredge.io/api/light-node/claim-node-points',
                                      "POST", headers, json_data, proxy)
        # print(f"[{address}] Запрос на очки: {response}")

        await asyncio.sleep(sleep)

        # 5. Получаем детали кошелька
        response = await make_request(session,
                                      f'https://referralapi.layeredge.io/api/referral/wallet-details/{address}',
                                      "GET", headers, proxy=proxy)

        node_points = response.get("data", {}).get("nodePoints", "Не найдено")
        print(f"🔹{i} || {address} Всего Node Points: {node_points}\n")

        return node_points

# Главная функция
async def main():
    # Загружаем приватные ключи и прокси
    private_keys = await load_lines_async("../txt/private_keys.txt")
    proxies = await load_lines_async("../txt/proxies.txt")

    # Убеждаемся, что число прокси >= число кошельков
    if len(proxies) < len(private_keys):
        print("⚠️ Внимание! Количество прокси меньше количества кошельков. Некоторым кошелькам прокси не хватит!")

    # Создаём семафор для ограничения количества потоков
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_TASKS)

    # Создаём сессию aiohttp
    async with aiohttp.ClientSession() as session:
        tasks = []
        for i, pk in enumerate(private_keys):
            proxy = proxies[i % len(proxies)]  # Назначаем прокси циклично
            tasks.append(process_wallet(session, pk, proxy, semaphore, i))

        node_points_list = await asyncio.gather(*tasks)

    # Выводим общие данные по всем кошелькам
    print("\n🔹 Итоговая статистика:")
    for i, pk in enumerate(private_keys):
        address = Account.from_key(pk).address
        print(f"[{address}] Итоговые Node Points: {node_points_list[i]}")

# Запуск программы
if __name__ == "__main__":
    asyncio.run(main())
