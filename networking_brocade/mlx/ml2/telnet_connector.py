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
import time

from networking_brocade._i18n import _
from networking_brocade._i18n import _LE
from networking_brocade.mlx.ml2 import device_connector as dev_conn
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

TELNET_PORT = 23
LOGIN_USER_TOKEN = "Name:"
LOGIN_PASS_TOKEN = "Password:"
PATTERN_EN_AUTH = '.*\\r\\n.*Name\\:$'
SUPER_USER_AUTH = '^Password\\:$'
TERMINAL_LENGTH = "terminal length 0"

END_OF_LINE = "\r"
PROMPT = ">"
ENABLE_PROMPT = '#'
CONFIGURE_TERMINAL = "#"
ENABLE_USERNAME_PROMPT = 'User Name:'
ENABLE_PASSWORD_PROMPT = 'Password:'
CONFIG_MODE = "(config)#"

RETURN_COMMAND = "\r"
ENABLE_COMMAND = "en\r"
CONFIG_COMMAND = "conf t\r"

MIN_TIMEOUT = 2
AVG_TIMEOUT = 4
MAX_TIMEOUT = 8


class TelnetConnector(dev_conn.DeviceConnector):

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
            self.response = str()
            self._enter_prompt(False)
        except Exception as e:
            LOG.exception(_LE("Connect failed to switch %(host)s with error"
                              " %(error)s"),
                          {'host': self.host, 'error': e.args})
            raise Exception(_("Connection Failed"))

    def _send_command(self, prompt, command):
        """
        Executes the command passed, if the response matches the prompt
        """
        execution_state = False
        if self.response.endswith(prompt):
            self.connector.write(command)
            execution_state = True
        return execution_state

    def _enter_prompt(self, is_config_mode):
        """
        Enters enable prompt mode or config mode based on the parameter

        param:is_config_mode: if this is True, will enter config mode, else
                              it will make sure it is in enable prompt.
        """
        commands = []
        prompt_command = {}
        if is_config_mode:
            prompts = [ENABLE_PROMPT, CONFIG_MODE]
            prompt_command = {ENABLE_PROMPT: CONFIG_COMMAND,
                              CONFIG_MODE: RETURN_COMMAND}
        else:
            prompts = [PROMPT, ENABLE_USERNAME_PROMPT,
                       ENABLE_PASSWORD_PROMPT, ENABLE_PROMPT]
            prompt_command = {PROMPT: ENABLE_COMMAND,
                              ENABLE_USERNAME_PROMPT: self.enable_username +
                              RETURN_COMMAND,
                              ENABLE_PASSWORD_PROMPT: self.enable_password +
                              RETURN_COMMAND,
                              ENABLE_PROMPT: RETURN_COMMAND}
        cmd_executed = True
        # Send new line so that channel will have something to read for the
        # first time.
        self.connector.write(RETURN_COMMAND)
        index = 0
        while index < len(commands):
            prompt = prompts[index]
            if cmd_executed:
                self.response += self.connector.read_until(prompt, AVG_TIMEOUT)
            command = prompt_command.get(prompt)
            cmd_executed = self._send_command(prompt, command)
            index += 1
            time.sleep(MIN_TIMEOUT)

    def enter_configuration_mode(self):
        """
        This method will ensure the session is in configuration mode
        """
        self._enter_prompt(True)

    def write(self, command):
        """
        Write from input stream to device

        :param:command: Command to be executed on the device
        """
        self.connector.write(command)
        self.response += self.connector.read_until(PROMPT, MAX_TIMEOUT)

    def read_response(self):
        """Read the response from the output stream.

        :returns: Response from the device as string.
        """
        return self.response

    def close_session(self):
        """Close TELNET session."""
        if self.connector:
            self.connector.close()
            self.connector = None
