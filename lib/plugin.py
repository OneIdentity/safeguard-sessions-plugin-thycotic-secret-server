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

from safeguard.sessions.plugin import PluginSDKRuntimeError
from safeguard.sessions.plugin.credentialstore_plugin import CredentialStorePlugin
from safeguard.sessions.plugin.host_resolver import HostResolver

from .client import Client


class Plugin(CredentialStorePlugin):
    PLUGIN_NAME = "ThycoticSecretServerPlugin"

    def __init__(self, configuration):
        super().__init__(configuration)
        self._domain_suffix = self.plugin_configuration.get('thycotic', 'domain_suffix')

    def _generate_assets(self):
        target_domain = self.connection.target_domain
        target_host = self.connection.target_ip

        yield {'search_field': 'Machine', 'value': target_host}

        if self.plugin_configuration.getboolean('thycotic', 'ip_resolving'):
            resolved_hosts = HostResolver.from_config(self.plugin_configuration).resolve_hosts_by_ip(target_host)
            for host in resolved_hosts:
                yield {'search_field': 'Machine', 'value': host}

        if target_domain:
            if self._domain_suffix:
                target_domain = '%s.%s' % (target_domain, self._domain_suffix)

            yield {'search_field': 'Domain', 'value': target_domain}

            if self.plugin_configuration.get('domain_asset_mapping', target_domain):
                yield {'search_field': 'Domain', 'value': self.plugin_configuration.get('domain_asset_mapping', target_domain)}

    def do_get_password_list(self):
        self.__client = Client.create(self.plugin_configuration,
                                      self.connection.gateway_user,
                                      self.connection.gateway_password)
        try:
            return self.__client.get_passwords(self.account, self.asset)
        except PluginSDKRuntimeError as ex:
            self.logger.error("Error retrieving passwords: {}".format(ex))
            return None

    def do_get_private_key_list(self):
        self.__client = Client.create(self.plugin_configuration,
                                      self.connection.gateway_user,
                                      self.connection.gateway_password)
        try:
            return self.__client.get_keys(self.account, self.asset)
        except PluginSDKRuntimeError as ex:
            self.logger.error("Error retrieving passwords: {}".format(ex))
            return None
