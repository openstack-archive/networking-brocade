===============================
networking-brocade
===============================

Brocade Networking Mech. Drivers and Plugins

* Free software: Apache license
* Source: http://git.openstack.org/cgit/stackforge/networking-brocade

The followin Mechanism Driver and Plugins are available in this repository:

1. VDX ML2 Mechanism Driver (L2)
2. VDX SVI Driver (L3)
3. ...

Documentation:

VDX ML2 Mechanism Driver:

* N.B.: Please see Prerequisites section  regarding ncclient (netconf client library)
* Supports VCS (Virtual Cluster of Switches)
* Issues/Questions/Bugs: sharis@brocade.com



   1. VDX 67xx series of switches
   2. VDX 87xx series of switches

ML2 plugin requires mechanism driver to support configuring of hardware switches.
Brocade Mechanism for ML2 uses NETCONF at the backend to configure the Brocade switch.
Currently the mechanism drivers support VLANs only.

             +------------+        +------------+          +-------------+
             |            |        |            |          |             |
   Neutron   |            |        |            |          |   Brocade   |
     v2.0    | Openstack  |        |  Brocade   |  NETCONF |  VCS Switch |
         ----+ Neutron    +--------+  Mechanism +----------+             |
             | ML2        |        |  Driver    |          |  VDX 67xx   |
             | Plugin     |        |            |          |  VDX 87xx   |
             |            |        |            |          |             |
             |            |        |            |          |             |
             +------------+        +------------+          +-------------+


Configuration

In order to use this mechnism the brocade configuration file needs to be edited with the appropriate
configuration information:

        % cat /etc/neutron/plugins/ml2/ml2_conf_brocade.ini
        [switch]
        username = admin
        password = password
        address  = <switch mgmt ip address>
        ostype   = NOS

Additionally the brocade mechanism driver needs to be enabled from the ml2 config file:

       % cat /etc/neutron/plugins/ml2/ml2_conf.ini

       [ml2]
       tenant_network_types = vlan
       type_drivers = local,flat,vlan,gre,vxlan
       mechanism_drivers = brocade
       ...













