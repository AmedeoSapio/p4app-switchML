#  Copyright 2021 Intel-KAUST-Microsoft
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import logging

from control import Control


class Forwarder(Control):

    def __init__(self, target, gc, bfrt_info, mgid):
        # Set up base class
        super(Forwarder, self).__init__(target, gc)

        self.log = logging.getLogger(__name__)

        self.tables = [bfrt_info.table_get('pipe.Ingress.forwarder.forward')]
        self.table = self.tables[0]

        # Annotations
        self.table.info.key_field_annotation_add('hdr.ethernet.dst_addr', 'mac')

        # Multicast group ID for flood
        self.mgid = mgid

        # Keep set of mac addresses so we can delete them all without deleting the flood rule
        self.fib = {}

        # Clear table and add defaults
        self._clear()
        self.add_default_entries()

    def _clear(self):
        ''' Remove all entries (except broadcast) '''

        self.table.entry_del(self.target, [
            self.table.make_key(
                [self.gc.KeyTuple('hdr.ethernet.dst_addr', mac_address)])
            for mac_address in self.fib
        ])
        self.fib.clear()

    def add_default_entries(self):
        ''' Add broadcast and default entries '''

        # Add broadcast entry
        self.table.entry_add(self.target, [
            self.table.make_key([
                self.gc.KeyTuple('hdr.ethernet.dst_addr', 'ff:ff:ff:ff:ff:ff')
            ])
        ], [
            self.table.make_data([self.gc.DataTuple('flood_mgid', self.mgid)],
                                 'Ingress.forwarder.flood')
        ])

        # Add default entry
        self.table.default_entry_set(
            self.target,
            self.table.make_data([self.gc.DataTuple('flood_mgid', self.mgid)],
                                 'Ingress.forwarder.flood'))

    def add_entry(self, mac_address, dev_port):
        ''' Add one entry.

            Keyword arguments:
                mac_address -- MAC address reachable through the port
                dev_port -- dev port number
        '''

        self.table.entry_add(self.target, [
            self.table.make_key(
                [self.gc.KeyTuple('hdr.ethernet.dst_addr', mac_address)])
        ], [
            self.table.make_data([self.gc.DataTuple('egress_port', dev_port)],
                                 'Ingress.forwarder.set_egress_port')
        ])
        self.fib[mac_address] = dev_port

    def add_entries(self, entry_list):
        ''' Add entries.

            Keyword arguments:
                entry_list -- a list of tuples: (mac_address, dev_port)
        '''

        for (mac_address, dev_port) in entry_list:
            self.add_entry(mac_address, dev_port)

    def remove_entry(self, mac_address):
        ''' Remove one entry '''
        self.table.entry_del(self.target, [
            self.table.make_key(
                [self.gc.KeyTuple('hdr.ethernet.dst_addr', mac_address)])
        ])
        del self.fib[mac_address]

    def get_dev_port(self, mac):
        ''' Get dev port for MAC address.

            Returns:
                (success flag, dev port or error message)
        '''

        mac = mac.upper()
        if mac not in self.fib:
            return (False, 'MAC address not found')
        return (True, self.fib[mac])

    def get_macs_on_port(self, dev_port):
        ''' Get MAC addresses associated to a dev port '''

        results = []
        for mac_address, port in self.fib.items():
            if port == dev_port:
                results.append(mac_address)

        return results

    def get_entries(self):
        ''' Get all forwarding entries.

            Returns:
                list of (MAC address, dev port)
        '''

        return self.fib.items()
