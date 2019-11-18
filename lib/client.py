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
    def __init__(self, requests_tls, address_url, username, password, authenticator):
        self.__requests_tls = requests_tls
        self.__address_url = address_url
        self.__username = username
        self.__password = password
        self.__authenticator = authenticator

    @classmethod
    def create(cls, config, gateway_username, gateway_password):
        requests_tls = RequestsTLS.from_config(config)
        address_url = '{}://{}'.format('https' if requests_tls.tls_enabled else 'http',
                                       config.get('thycotic', 'address', required=True))

        (username, password) = cls.get_username_password(config, gateway_username, gateway_password)

        return Client(
            requests_tls=requests_tls,
            address_url=address_url,
            username=username,
            password=password,
            authenticator=AuthenticatorFactory.create(config)
        )

    @classmethod
    def get_username_password(cls, config, gateway_username, gateway_password):
        use_credential = config.getienum('thycotic', 'use_credential', ('explicit', 'gateway'), default='gateway')
        if use_credential == 'explicit':
            return config.get('thycotic', 'username', required=True), config.get('cyberark', 'password', required=True)
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

    def get_passwords(self, account, asset, gateway_username):
        with self.__requests_tls.open_session() as session:
            auth_token = self.__authenticator.authenticate(
                session,
                self.__address_url,
                self.__username,
                self.__password
            )
            passwords = self.__get_passwords(session, auth_token, account, asset, gateway_username)
            self.__authenticator.logoff(session, self.__address_url)
        return passwords

    def __get_passwords(self, session, auth_token, account, asset, gateway_username):
        headers = {'Content-Type': 'application/json', 'Authorization': auth_token}
        found_objects = _extract_data_from_endpoint(
            session,
            endpoint_url=(self.__address_url + '/PasswordVault/api/Accounts?search=' +
                          ','.join([account, asset]) + '&sort=UserName'),
            headers=headers,
            method='get',
            field_name='value'
        )


        found_objects = list(filter(lambda x: (account == x.get('userName') and asset == x.get('address')),
                                    found_objects))
        if len(found_objects) == 0:
            logger.debug('No objects found in vault for this account and/or asset: account={}, asset={}'
                         .format(account, asset))
            return {'passwords': []}

        pwd_post_data = {
            'reason': '{},SPS'.format(gateway_username),
            'TicketingSystemName': '',
            'TicketId': '',
            'Version': 0,
            'ActionType': 'show',
            'isUse': False,
            'Machine': asset
        }

        passwords = []
        for found_object in found_objects:
            endpoint_url = self.__address_url + '/PasswordVault/api/Accounts/' + found_object.get('id') + '/Password/Retrieve'
            passwords.append(_extract_data_from_endpoint(session, endpoint_url, headers, 'post', None, pwd_post_data))

        return {'passwords': passwords}


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


class AuthenticatorFactory:
    @classmethod
    def create(cls, config):
        authentication_method = config.getienum(
            'thycotic',
            'authentication_method'
        )
        return Authenticator(authentication_method)


class Authenticator:
    def __init__(self, auth_type):
        self._authorization = None
        self._type = auth_type
    TYPES = ('thycotic', 'ldap', 'radius', 'windows')
    TYPE_TO_ENDPOINT = {
        'thycotic': 'Thycotic',
        'ldap': 'LDAP',
        'radius': 'radius',
        'windows': 'Windows'
    }

    def authenticate(self, session, base_url, username, password):
        auth_post_data = {
            'username': username,
            'password': password,
            'grant_type': 'password'
        }
        self._authorization = _extract_data_from_endpoint(
            session,
            endpoint_url=base_url + '/oauth2/token',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            method='post',
            data=auth_post_data
        )
        return self._authorization

    def logoff(self, session, url):
        if self._authorization is None:
            return
        logger.debug('Logoff from Thycotic Secret Server; url={}'.format(url))
        try:
            response = session.post(
                url,
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': self._authorization
                }
            )
            if not response.ok:
                logger.warning('Logoff from Thycotic Secret Server failed; status={}'.format(response.status_code))
        except requests.exceptions.RequestException as ex:
            logger.warning('Logoff from Thycotic Secret Server failed; exception={}'.format(ex))
