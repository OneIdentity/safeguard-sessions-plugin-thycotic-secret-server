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

from .client import Client


class Plugin(CredentialStorePlugin):
    PLUGIN_NAME = "ThycoticSecretServerPlugin"

    def __init__(self, configuration):
        super().__init__(configuration)
        self.__client = Client.create(self.plugin_configuration,
                                      self.connection.gateway_user,
                                      self.connection.gateway_password)

    def do_get_password_list(self):
        try:
            return self.__client.get_passwords(self.account, self.asset, self.connection.gateway_username)
        except PluginSDKRuntimeError as ex:
            self.logger.error("Error retrieving passwords: {}".format(ex))
            return None

    def do_get_private_key_list(self):
        try:
            return self.__client.get_private_keys(self.account, self.asset, self.connection.gateway_username)
        except PluginSDKRuntimeError as ex:
            self.logger.error("Error retrieving passwords: {}".format(ex))
            return None
