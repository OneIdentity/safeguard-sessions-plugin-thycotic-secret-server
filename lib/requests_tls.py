#
# Copyright (c) 2006-2019 Balabit
# All Rights Reserved.
#
"""
.. py:module:: safeguard.sessions.plugin.requests_tls
    :synopsis: Service to create a python requests Session object with configured TLS.

The RequestsTLS service provides means to instantiate a requests.Session object with
TLS settings set with respect to plugin configuration.

*New in version 1.3.0.*

Configuration example
=====================
.. code-block:: ini

    [tls]
    # Set to 'no' to disable TLS completely
    # Default is 'yes'
    ; enabled = yes

    # Set this option to enable client side verification. Certificate from the
    # server will be checked with this CA. If the value of the option is `$[<name>]`
    # the certificates are retrieved from the trusted CA list configured on the SPS,
    # identified by the name. When the certificate is given in the configuration, it
    # should be in PEM format and all the new lines must be indented with one
    # whitespace. If it is a chain, put the certificates right after each other.
    ; ca_cert = <ca-certificate-chain>
    ; ca_cert = $[<trusted_ca_list_name>]

    # Client certificate, set this if verification is enabled on server side
    # If the value of the option is `$` the certificate identified by the section
    # and option pair is retrieved from the configured credential store. When the
    # certificate and private key is given in the configuration it should be in
    # PEM format and all the new lines must be indented with one whitespace. Note
    # that encrypted keys are not supported.
    ; client_cert = <client-certificate-and-key>

Getting a Session object
========================

After getting a session object, it can be used as a standard requests session to make API calls

.. code-block:: python

    from safeguard.sessions.plugin.requests_tls import RequestsTLS

    class Plugin(PluginBase):
        def hook(self):
            requests_tls = RequestsTLS.from_config(self.plugin_configuration)
            with requests_tls.open_session() as session:
                session.get('https://httpbin.org')
"""

from requests import Session
from tempfile import mkstemp
from contextlib import suppress
from os import remove
from contextlib import contextmanager


class RequestsTLS:

    def __init__(self, enabled=True, ca_cert=None, client_cert=None):
        self.__session = None
        self.__enabled = enabled
        self.__ca_cert = ca_cert
        self.__client_cert = client_cert
        self.__ca_tmp = None
        self.__client_tmp = None

    @property
    def tls_enabled(self):
        return self.__enabled

    @contextmanager
    def open_session(self):
        self.__session = Session()
        self.__session.verify = False
        self.__session.cert = False
        if self.__enabled:
            if self.__ca_cert:
                if self.__ca_cert.get('location'):
                    self.__session.verify = self.__ca_cert['location']
                else:
                    blobs = [blob.strip('\n') for blob in self.__ca_cert['certs']]
                    self.__session.verify = _write_into_temp_file(blobs)
            if self.__client_cert:
                blobs = [blob.strip('\n') for blob in [self.__client_cert['cert'], self.__client_cert['key']]]
                self.__session.cert = _write_into_temp_file(blobs)

        yield self.__session

        self.__session.close()
        self.__session = None
        with suppress(FileNotFoundError):
            if self.__ca_tmp:
                remove(self.__ca_tmp)
            if self.__client_tmp:
                remove(self.__client_tmp)

    @classmethod
    def from_config(cls, plugin_configuration, section='tls', enabled=None, ca_cert=None, client_cert=None):
        enabled = enabled or plugin_configuration.getboolean(section, 'enabled', default=True)
        ca_cert = None # ca_cert or plugin_configuration.get_ca_certificate(section, 'ca_cert', default=None)
        client_cert = None # client_cert or plugin_configuration.get_certificate(section, 'client_cert', default=None)
        return RequestsTLS(enabled, ca_cert, client_cert)


def _write_into_temp_file(blobs):
    file_desc, temp_file_name = mkstemp(text=True)
    with open(file_desc, 'w') as f:
        f.write('\n'.join(blobs))
    return temp_file_name
