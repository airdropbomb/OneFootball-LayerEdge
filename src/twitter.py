import base64
import os
import hashlib
from typing import Optional

from curl_cffi.requests import AsyncSession
from loguru import logger

from src.data import COMMON_HEADERS
from src.utils import _make_request, user_login

def save_token(auth_token: str, filename, address=None, private_key = None):

    try:
        if filename == 'bad_tokens.txt':
            with open('bad_tokens.txt', "a") as f:
                f.write(auth_token + "\n")
        else:
            with open('connected_token.txt', "a") as f:
                f.write(f'{auth_token} || {address} || {private_key}\n')
    except Exception as e:
        logger.error(f"Ошибка при сохранении токена {auth_token}: {e}")

def generate_code_verifier(length=32):
    """Генерация случайного code_verifier"""
    random_bytes = os.urandom(length)
    return base64.urlsafe_b64encode(random_bytes).rstrip(b'=').decode('utf-8')

def generate_code_challenge(code_verifier):
    """Создание code_challenge на основе SHA-256"""
    sha256_hash = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(sha256_hash).rstrip(b'=').decode('utf-8')

def generate_random_state():
    """Генерация state_code в нужном формате"""
    while True:
        random_bytes = os.urandom(36)  # 32 байта → ~43 символа после Base64 URL-safe encoding
        state_code = base64.urlsafe_b64encode(random_bytes).rstrip(b'=').decode('utf-8')

        # Проверяем, содержит ли строка нужные символы
        if "-" in state_code or "_" in state_code:
            if len(state_code) == 48:
                return state_code

import random
import re
from urllib.parse import urlparse, parse_qs
import requests
from fake_useragent import UserAgent
from loguru import logger
import concurrent.futures

ua = UserAgent()

class Account:
    _standart_data = {'approval': 'true'}
    _authorize_url = "https://x.com/i/api/2/oauth2/authorize"
    _authorization = 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA'

    def __init__(self, auth_token: str, proxy: str, session):
        self.auth_token = auth_token
        self.useragent = ua.random
        self.session = session

        self.cookies = {'auth_token': self.auth_token}
        self.headers = {'authorization': self._authorization, 'user-agent': self.useragent}
        self.proxy = proxy

    async def _get_auth_code(self, data: dict):
        response =await _make_request(session=self.session,url=self._authorize_url, params=data,headers=self.headers,cookies=self.cookies, proxy=self.proxy, method='GET')
        if response.status_code ==401:
            logger.error(f'Auth {self.auth_token} не работает')
            save_token(self.auth_token, 'bad_tokens.txt')  # Добавляем в список нерабочих токенов
            return None
        set_cookie_value = response.headers['set-cookie']
        ct0 = re.search(r'ct0=([a-f0-9]+)', set_cookie_value).group(1)

        self.cookies['ct0'] = ct0
        self.headers['x-csrf-token'] = ct0
        response =await _make_request(session=self.session,url=self._authorize_url, params=data,headers=self.headers,cookies=self.cookies, proxy=self.proxy, method='GET')

        response_json = response.json()
        return response_json['auth_code']

    async def _get_redirect_uri(self, auth_code: str):
        data = self._standart_data
        data['code'] = auth_code
        response =await _make_request(session=self.session,url=self._authorize_url, params=data,headers=self.headers,cookies=self.cookies, proxy=self.proxy)

        return response['redirect_uri']

    async def authorize(self, data: dict, referer_url: str):
        self.headers['referer'] = referer_url
        auth_code = await self._get_auth_code(data)
        if auth_code is None:
            return None, None
        redirect_uri = await self._get_redirect_uri(auth_code)
        return auth_code, redirect_uri


def get_oauth2_data(url):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    return {
        'response_type': query_params.get('response_type', [''])[0],
        'client_id': query_params.get('client_id', [''])[0],
        'redirect_uri': query_params.get('redirect_uri', [''])[0],
        'scope': query_params.get('scope', [''])[0],
        'state': query_params.get('state', [''])[0],
        'code_challenge': query_params.get('code_challenge', [''])[0],
        'code_challenge_method': query_params.get('code_challenge_method', [''])[0],
    }


async def get_authorize_data(session, useragent, proxy, token):
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    state_code = generate_random_state()

    json_data = {
        'provider': 'twitter',
        'redirect_to': 'https://ofc.onefootball.com/s2/',
        'code_challenge': code_challenge,
        'state_code': state_code,
    }
    headers = {
        **COMMON_HEADERS,
        'privy-app-id': 'clphlvsh3034xjw0fvs59mrdc',
        'privy-client': 'react-auth:1.80.0-beta-20240821191745',
        'authorization': f'Bearer {token}',
    }

    response = await _make_request(session,'https://auth.privy.io/api/v1/oauth/init', headers=headers,json_data=json_data, proxy=proxy)
    return response['url'], state_code, code_verifier, code_challenge

async def post_auth(session, state, auth_code, useragent, proxy):
    headers = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
        'cache-control': 'no-cache',
        'dnt': '1',
        'pragma': 'no-cache',
        'priority': 'u=0, i',
        'referer': 'https://x.com/',
        'sec-ch-ua': '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'cross-site',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': useragent,
    }
    params = {
        'state': state,
        'code': auth_code,
    }
    response = await _make_request(session, url='https://auth.privy.io/api/v1/oauth/callback',params=params, headers=headers, proxy=proxy, method='GET', allow_redirects=False)

    location_url = response.headers.get("Location")
    if location_url:
        logger.debug("Перенаправление на:", location_url)
    else:
        logger.error("Заголовок 'Location' отсутствует в ответе.")
    parsed_url = urlparse(location_url)

    # Извлекаем параметры
    params = parse_qs(parsed_url.query)
    # Записываем параметры в переменные
    privy_oauth_state = params.get('privy_oauth_state', [''])[0]
    privy_oauth_code = params.get('privy_oauth_code', [''])[0]

    return location_url,privy_oauth_state,privy_oauth_code


async def join(session, useragent, proxy, url):
    headers = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
        'cache-control': 'no-cache',
        'dnt': '1',
        'pragma': 'no-cache',
        'priority': 'u=0, i',
        'referer': 'https://x.com/',
        'sec-ch-ua': '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'cross-site',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': useragent,
    }

    response = await _make_request(session, url=url, headers=headers, proxy=proxy, method='GET')
    return response


async def check_joined(session, authorization_code, state_code, code_verifier, proxy, useragent, user_token, auf, address, private_key):

    json_data = {
        'authorization_code': authorization_code,
        'state_code': state_code,
        'code_verifier': code_verifier,
    }

    headers = {
        'accept': 'application/json',
        'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
         'authorization': f'Bearer {user_token}',
        'cache-control': 'no-cache',
        'content-type': 'application/json',
        'dnt': '1',
        'origin': 'https://club.onefootball.com',
        'pragma': 'no-cache',
        'priority': 'u=1, i',
        'privy-app-id': 'clphlvsh3034xjw0fvs59mrdc',
        'privy-ca-id': '30402c22-09d6-417d-a89c-6679241695e8',
        'privy-client': 'react-auth:1.80.0-beta-20240821191745',
        'referer': 'https://club.onefootball.com/',
        'sec-ch-ua': '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': useragent,
    }

    response = await _make_request(session, url='https://auth.privy.io/api/v1/oauth/link',json_data=json_data, headers=headers, proxy=proxy)
    if response.get('error') == 'Another user has already linked this Twitter account' and response.get(
            'code') == 'linked_to_another_user':
        logger.error("Another user has already linked this Twitter account")
    twitter_username = None
    for account2 in response.get('linked_accounts', []):
        if account2.get('type') == 'twitter_oauth':
            twitter_username = account2.get('username')
            break
    if twitter_username:
        logger.success(f'{twitter_username} - registered')
        save_token(auf, 'connected_token.txt', address, private_key)
    else:
        logger.error(f'Не удалось подключить твитер || {auf}')

async def twitter(session: AsyncSession, proxy: Optional[str], token: str, account_auth_token, address, private_key):
    account = Account(auth_token=account_auth_token, proxy=proxy, session=session)
    authorize_url, state, code_verifier, code_challenge = await get_authorize_data(session,account.useragent, proxy, token)
    oauth2_data = get_oauth2_data(authorize_url)
    auth_code, redirect_url =await account.authorize(oauth2_data, authorize_url)
    if not auth_code: return
    url, privy_oauth_state, privy_oauth_code = await post_auth(session, state, auth_code, account.useragent, proxy)

    await join(session, account.useragent, proxy, url)

    await check_joined(session, privy_oauth_code, privy_oauth_state, code_verifier, proxy, account.useragent, token, account_auth_token, address, private_key)