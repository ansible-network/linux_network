Role Name
=========

This Ansible network role provides functionality to send packets from a host based on an input JSON of packet keys like source ip address , destination ip address etc

Requirements
------------

- Ansible 2.6 or later
- scapy python module

Role Variables
--------------

- tgn_flows_filepath:
    - description:
      - This value is used to specifiy a file with flows info which will be used
        to send packets from this tgn. It is JSON encoded file with flows info
        like source ip, source port, destination port etc
    - example: templates/example_packet_dict.json
    - required: True

-  tgn_out_port:
    - description:
      - This value specifies a port on TGN which will be used to send packets
        from the device. This port should have L3 connectivity to DUT to send
        traffic for verification of service
    - required: True
  
- tgn_l3_gateway:
    - description:
      - This value specifies default L3 gateway to send packets towards DUT.
    - required: True

- tgn_wildcard_dest:
    - description:
      - This value is used to identify an internet host. A service (e.g. ACL) might be
        used to control access to internet. A destination ip would be 'any' in that case.
        traffic generator would use this value to verify access to internet is working as
        intended. This option is required only if your service has 'any' type of destination
        ip to be tested
    - required: False

Dependencies
------------

None

Example Playbook
----------------
    - hosts: servers
      roles:
         - { role: ansible-network.linux_tgn }

License
-------

GPLv3

Author Information
------------------

Ansible network Team
