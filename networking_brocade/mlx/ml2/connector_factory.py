# Copyright 2015 Brocade Communications System, Inc.
# All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
    Connector class used to connect to device.
    Decides which connector to use - TELNET or SSH, based on
    the argument passed
"""

from oslo_utils import importutils


class ConnectorFactory(object):
    """
    Connector class used to connect to device.
    Decides which connector to use - TELNET or SSH, based on
    the argument passed
    """

    connectors = {"SSH": "networking_brocade.mlx.ml2.ssh_connector."
                  "SSHConnector",
                  "TELNET": "networking_brocade.mlx.ml2."
                            "telnet_connector.TelnetConnector"
                  }

    def get_connector(self, device_info):
        """
        Returns the connector based on the transport to be used

        :param:device_info: Device details in the form of dictionary
        :returns: Connector for the device based on the transport parameter.
            Currently only SSH is supported and it is the default connector
            that is returned.
        """
        transport = device_info.get('transport')
        connector = self.connectors.get(transport)
        connection = importutils.import_object(connector, device_info)
        return connection
