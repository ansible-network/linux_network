#!/usr/bin/python
#
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
---
module: send_traffic 
version_added: "2.7"
author: "Deepak Agrawal (@dagrawal)"
short_description: send traffic from device as per given packet header
description:
  - This module sends traffic from a port on a device with given
    packet headers in JSON list
options:
    src:
      description: path of file containing packet header dictionary
      required: true
    port:
      description: port on device which can reach DUT to send traffic.
      required: true

version_added: "2.7"
notes:
"""

EXAMPLES = """
- name: Send traffc
  send_traffic
    src: ~/net_op/packet_dict.json
    port: enp0s16
"""

RETURN = """
"""
import re
import sys
import os
import json
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text, to_bytes

class TrafficGen(object):
    def __init__(self, module, pd_path, port, gw, any_dest):
        self._pd = pd_path
        self._port = port
        self._module = module
        self._wildcard_dest = any_dest
        self._gw = gw

    def load_packets(self, packet_src):
        if os.path.exists(packet_src):
            with open(packet_src, 'r') as f:
                packet_content = f.read()
            packet_d = json.loads(packet_content)
            self._packets = packet_d
        else:
            raise IOError("src file not found")

    def send_packets(self):
        from scapy.all import *

        for packet in self._packets:
            if packet['src'] != 'any':
                frame = IP(src=str(packet['src']))
            else:
                frame = IP(src=self._gw) #FIXME
            if packet['dst'] != 'any':
                frame.dst = packet['dst']
            else:
                frame.dst = self._wildcard_dest

            if 'proto' in packet:
                if packet['proto'] == 'tcp':
                   if 'src_port' in packet:
                       tcp = TCP(sport=int(packet['src_port']))
                       if 'dst_port' in packet:
                           tcp.dport = int(packet['dst_port'])
                   elif 'dst_port' in packet:
                       tcp = TCP(dport=int(packet['dst_port']))
                   else:
                       # FIXME
                       tcp = TCP(dport=22)
                   frame = frame / tcp
    
                if packet['proto'] == 'udp':
                   if 'src_port' in packet:
                       udp = UDP(sport=int(packet['src_port']))
                       if 'dst_port' in packet:
                           udp.dport = int(packet['dst_port'])
                   elif 'dst_port' in packet:
                       udp = UDP(dport=int(packet['dst_port']))
                   else:
                       # FIXME: what should be default port
                       udp = UDP(dport=22)
                   frame = frame / udp

            # Now add Host route via Gateway and port of TGN
            # Route will be deleted after exit from this process
            conf.route.add(host=frame.dst, gw=self._gw, dev=self._port)
            # Send packet
            send(frame)

    def main(self):
        try:
            self.load_packets(self._pd)
        except Exception as e:
            raise e
        self.send_packets()

def main():
    """main entry point for module execution
    """
    argument_spec = dict(
        src=dict(required=True, type='path'),
        port=dict(required=True),
        gateway=dict(required=True),
        wildcard_dest=dict(required=True)
    )
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    p = module.params
    tg = TrafficGen(module, p['src'], p['port'], p['gateway'], p['wildcard_dest'])
    try:
        tg.main()
    except Exception as e:
        module.fail_json(msg=to_text(e))

    warnings = list()
    result = dict(changed=False, warnings=warnings)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
