#
#   Copyright (c) 2019 One Identity
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
import json
import requests

from safeguard.sessions.plugin.exceptions import PluginSDKRuntimeError
from safeguard.sessions.plugin.requests_tls import RequestsTLS
from safeguard.sessions.plugin.logging import get_logger


logger = get_logger(__name__)


class ThycoticException(Exception):
    pass


class Client:
    def __init__(self, requests_tls, base_url, username, password, authenticator):
        self.__requests_tls = requests_tls
        self.__base_url = base_url
        self.__username = username
        self.__password = password
        self.__authenticator = authenticator
        self.__headers = {}

    @classmethod
    def create(cls, config, gateway_username, gateway_password):
        requests_tls = RequestsTLS.from_config(config)
        base_url = '{}://{}'.format('https' if requests_tls.tls_enabled else 'http',
                                       config.get('thycotic', 'address', required=True))

        (username, password) = cls.get_username_password(config, gateway_username, gateway_password)

        return Client(
            requests_tls=requests_tls,
            base_url=base_url,
            username=username,
            password=password,
            authenticator=Authenticator()
        )

    @classmethod
    def get_username_password(cls, config, gateway_username, gateway_password):
        use_credential = config.getienum('thycotic', 'use_credential', ('explicit', 'gateway'), default='gateway')
        if use_credential == 'explicit':
            return config.get('thycotic', 'username', required=True), config.get('thycotic', 'password', required=True)
        else:
            if gateway_username and gateway_password:
                return gateway_username, gateway_password
            else:
                raise PluginSDKRuntimeError(
                    "Gateway username or password undefined and use_credentials is set to gateway",
                    {
                        "gateway_username": "N/A" if not gateway_username else gateway_username,
                        "gateway_password": "N/A" if not gateway_password else "(hidden)"
                    }
                )

    def get_passwords(self, account, asset):
        with self.__requests_tls.open_session() as session:
            access_token = self.__authenticator.authenticate(
                session,
                self.__base_url,
                self.__username,
                self.__password
            )
            self.__headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(access_token)}
            passwords = self.__get_secrets(session, account, asset, 'Password')
            self.__authenticator.logoff(session, self.__base_url)

            return {'passwords': passwords}

    def get_keys(self, account, asset):
        with self.__requests_tls.open_session() as session:
            auth_token = self.__authenticator.authenticate(
                session,
                self.__base_url,
                self.__username,
                self.__password
            )
            self.__headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(auth_token)}
            keys = self.__get_secrets(session, account, asset, 'Private key')
            self.__authenticator.logoff(session, self.__base_url)

            return {'private_keys': Client.format_keys(keys)}

    def __get_secrets(self, session, account, asset, field_name):
        endpoint_url = (self.__base_url +
                        '/api/v1/secrets?filter.includeRestricted=false&filter.searchtext={}'.format(account))
        user_secrets = _extract_data_from_endpoint(session, endpoint_url, self.__headers, 'get', field_name='records')
        user_secret_ids = [secret['id'] for secret in user_secrets]
        credentials = [self.__get_secret_content(session, _id, asset, field_name) for _id in user_secret_ids]
        return credentials

    def __get_secret_content(self, session, secret_id, asset, field_name):
        endpoint_url = self.__base_url + "/api/v1/secrets/{}".format(secret_id)
        secret_items = _extract_data_from_endpoint(session, endpoint_url, self.__headers, 'get', field_name='items')
        for item in secret_items:
            if item['fieldName'] == 'Machine':
                if item['itemValue'] == asset:
                    break
                else:
                    return
            else:
                continue
        else:
            return

        for item in secret_items:
            if item['fieldName'] == field_name:
                return item['itemValue']
        else:
            return

    @staticmethod
    def format_keys(keys):
        return [(Client.determine_keytype(key), key) for key in keys]

    @staticmethod
    def determine_keytype(key):
        if key.startswith('-----BEGIN RSA PRIVATE KEY-----'):
            return 'ssh-rsa'
        elif key.startswith('-----BEGIN DSA PRIVATE KEY-----'):
            return 'ssh-dss'
        else:
            logger.error('Unsupported key type')



def _extract_data_from_endpoint(session, endpoint_url, headers, method, field_name=None, data=None):
    logger.debug('Sending http request to Thycotic Secret Server, endpoint_url="{}", method="{}"'
                 .format(endpoint_url, method))
    try:
        if method == 'get':
            response = session.get(endpoint_url, headers=headers)
        elif data:
            response = session.post(endpoint_url, headers=headers, data=json.dumps(data) if data else None)
    except requests.exceptions.ConnectionError as exc:
        raise ThycoticException('Connection error: {}'.format(exc))
    if response.ok:
        logger.debug('Got correct response from endpoint: {}'.format(endpoint_url))
        content = json.loads(response.text)
        return content.get(field_name) if field_name else content
    else:
        raise ThycoticException('Received error from Thycotic Secret Server: {}'
                                .format(json.loads(response.text).get('ErrorMessage')))


class Authenticator:

    AUTHENTICATION_ENDPOINT = "/ouath2/token"
    GRANT_TYPE = "password"

    def get_access_token(self, session, base_url, username, password):
        url = base_url + self.AUTHENTICATION_ENDPOINT
        data = {
            'username': username,
            'password': password,
            'grant_type': self.GRANT_TYPE,
        }
        headers = {
            'Content-type': 'application/x-www-form-urlencoded',
        }
        return _extract_data_from_endpoint(
            session,
            url,
            headers,
            'post',
            field_name='access_token',
            data=data)
