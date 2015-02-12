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

from neutron.i18n import _LE
from neutron.openstack.common import log as logging
import neutron.plugins.ml2.drivers.brocade.commands as Commands
import neutron.plugins.ml2.drivers.brocade.device_connector as DeviceConnector
import paramiko

LOG = logging.getLogger(__name__)
WRITE = "wb"
READ = "rb"


class SSHConnector(DeviceConnector):

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

            channel = self.connector.invoke_shell()
            self.stdin_stream = channel.makefile(WRITE)
            self.stdout_stream = channel.makefile(READ)
            self.stderr_stream = channel.makefile(READ)

        except Exception as e:
            LOG.exception(_LE("Connect failed to switch %(host)s with error"
                              " %(error)s"),
                          {'host': self.host, 'error': e.args})
            raise Exception(_("Connection Failed"))

    def write(self, command):
        """
        Write from input stream to device
        """
        self.stdin_stream.write(command)
        self.stdin_stream.flush()

    def read_response(self, read_lines=True):
        """Read the response from the output stream."""
        response = None
        if read_lines is True:
            response = self.stdout_stream.readlines()
        else:
            response = self.stdout_stream.read()
        return response

    def send_exit(self, count):
        """Send Exit command."""
        index = 0
        while index < count:
            self.stdin_stream.write(Commands.EXIT)
            self.stdin_stream.flush()
            index += 1

    def close_session(self):
        """Close SSH session."""
        if self.connector:
            self.stdin_stream.close()
            self.stdout_stream.close()
            self.stderr_stream.close()
            self.connector.close()
