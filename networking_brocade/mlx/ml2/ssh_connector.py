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

""" Implementation of SSH Connector"""

from networking_brocade._i18n import _
from networking_brocade._i18n import _LE
from networking_brocade.mlx.ml2 import device_connector as dev_conn
from oslo_log import log as logging

import paramiko
import time

LOG = logging.getLogger(__name__)
PROMPT = '>'
ENABLE_PROMPT = '#'
ENABLE_USERNAME_PROMPT = 'User Name:'
ENABLE_PASSWORD_PROMPT = 'Password:'
CONFIG_MODE = '(config)#'

CONFIG_COMMAND = "conf t\n"
ENABLE_COMMAND = "en\n"
NEW_LINE = "\n"

TIMEOUT = 30.0
SLEEP_TIME = 1


class SSHConnector(dev_conn.DeviceConnector):

    """
    Uses SSH to connect to device
    """

    def connect(self):
        """
        Connect to the device
        """
        try:
            self.connector = paramiko.SSHClient()
            self.connector.set_missing_host_key_policy(
                paramiko.AutoAddPolicy())
            self.connector.connect(
                hostname=self.host,
                username=self.username,
                password=self.password)

            self.channel = self.connector.invoke_shell()
            self.channel.settimeout(TIMEOUT)
            self.channel_data = str()
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
        if self.channel_data.endswith(prompt):
            self.channel.send(command)
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
                              CONFIG_MODE: NEW_LINE}
        else:
            prompts = [PROMPT, ENABLE_USERNAME_PROMPT,
                       ENABLE_PASSWORD_PROMPT, ENABLE_PROMPT]
            prompt_command = {PROMPT: ENABLE_COMMAND,
                              ENABLE_USERNAME_PROMPT: self.enable_username +
                              NEW_LINE,
                              ENABLE_PASSWORD_PROMPT: self.enable_password +
                              NEW_LINE,
                              ENABLE_PROMPT: NEW_LINE}
        cmd_executed = True
        # Send new line so that channel will have something to read for the
        # first time.
        self.channel.send(NEW_LINE)
        index = 0
        while index < len(commands):
            prompt = prompts[index]
            if cmd_executed:
                self.channel_data += self.channel.recv(9999)
            command = prompt_command.get(prompt)
            cmd_executed = self._send_command(prompt, command)
            index += 1
            time.sleep(SLEEP_TIME)

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
        self.channel.send(command)
        time.sleep(SLEEP_TIME)
        self.channel_data += self.channel.recv(9999)

    def read_response(self, read_lines=True):
        """Read the response from the output stream.
        """
        return self.channel_data

    def close_session(self):
        """Close SSH session."""
        if self.connector:
            self.channel.close()
            self.connector.close()
