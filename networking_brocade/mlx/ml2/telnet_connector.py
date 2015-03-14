# Copyright 2015 Brocade Communications System, Inc.
# All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

""" Implementation of Telnet Connector """

import telnetlib

from networking_brocade.mlx.ml2.device_connector import (
    DeviceConnector as DevConn)
from neutron.i18n import _LE
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

TELNET_PORT = 23
LOGIN_USER_TOKEN = "Name:"
LOGIN_PASS_TOKEN = "Password:"
PATTERN_EN_AUTH = '.*\\r\\n.*Name\\:$'
SUPER_USER_AUTH = '^Password\\:$'
TERMINAL_LENGTH = "terminal length 0"

END_OF_LINE = "\r"
TELNET_TERMINAL = ">"
CONFIGURE_TERMINAL = "#"

MIN_TIMEOUT = 2
AVG_TIMEOUT = 4
MAX_TIMEOUT = 8


class TelnetConnector(DevConn):

    """
    Uses Telnet to connect to device
    """

    def connect(self):
        """
        Connect to device via Telnet
        """
        try:
            self.connector = telnetlib.Telnet(host=self.host, port=TELNET_PORT)
            self.connector.read_until(LOGIN_USER_TOKEN, MIN_TIMEOUT)
            self.connector.write(self.username + END_OF_LINE)
            self.connector.read_until(LOGIN_PASS_TOKEN, AVG_TIMEOUT)
            self.connector.write(self.password + END_OF_LINE)
            self.connector.read_until(TELNET_TERMINAL, MAX_TIMEOUT)
        except Exception as e:
            LOG.exception(_LE("Connect failed to switch %(host)s with error"
                              " %(error)s"),
                          {'host': self.host, 'error': e.args})
            raise Exception(_("Connection Failed"))

    def write(self, command):
        """
        Write from input stream to device

        :param:command: Command to be executed on the device
        """
        self.connector.write(command)

    def read_response(self, read_lines=True):
        """Read the response from the output stream.

        :param:read_lines: This is used only by the SSH connector.
        :returns: Response from the device as list.
        """
        return self.connector.read_until(CONFIGURE_TERMINAL, MIN_TIMEOUT)

    def close_session(self):
        """Close TELNET session."""
        if self.connector:
            self.connector.close()
            self.connector = None

    def send_exit(self, count):
        """No operation. Used by SSH connector only."""
        pass
