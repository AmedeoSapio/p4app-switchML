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

from common import front_panel_regex, mac_address_regex, validate_ip
from cli import Cli
from grpc_server import GRPCServer
from udp_sender import UDPSender
from rdma_sender import RDMASender
from next_step_selector import NextStepSelector
from processor import Processor
from exponents import Exponents
from workers_counter import WorkersCounter
from bitmap_checker import BitmapChecker
from udp_receiver import UDPReceiver
from rdma_receiver import RDMAReceiver
from drop_simulator import DropSimulator
from arp_icmp_responder import ARPandICMPResponder
from pre import PRE
from ports import Ports
from forwarder import Forwarder
from pool import Pool

import bfrt_grpc.client as gc
import os
import sys
import glob
import yaml
import signal
import asyncio
import argparse
import logging

# Add BF Python to search path
bfrt_location = '{}/lib/python*/site-packages/tofino'.format(
    os.environ['SDE_INSTALL'])
sys.path.append(glob.glob(bfrt_location)[0])


class SwitchML(object):
    '''SwitchML controller'''

    def __init__(self):
        super(SwitchML, self).__init__()

        self.log = logging.getLogger(__name__)
        self.log.info('SwitchML controller')

        # CPU PCIe port
        self.cpu_port = 320  # Pipe 2 Quad 16

        # UDP port and mask
        self.udp_port = 0xbee0
        self.udp_mask = 0xfff0

        # RDMA partition key
        self.switch_pkey = 0xffff

        # Pool of slots
        self.pool = Pool()

        # Set all nodes MGID
        self.all_ports_mgid = 0x8000
        self.all_ports_initial_rid = 0x8000

        # Multicast group ID -> replication ID (= node ID) -> port
        self.multicast_groups = {self.all_ports_mgid: {}}

        # Worker IP -> session ID
        self.worker_ip_to_session = {}

        # Session ID -> base index
        self.session_to_base_index = {}

    def critical_error(self, msg):
        self.log.critical(msg)
        print(msg, file=sys.stderr)
        logging.shutdown()
        # sys.exit(1)
        os.kill(os.getpid(), signal.SIGTERM)

    def setup(self,
              program,
              switch_mac,
              switch_ip,
              bfrt_ip,
              bfrt_port,
              ports_file,
              folded_pipe=False):

        # Device 0
        self.dev = 0
        # Target all pipes
        self.target = gc.Target(self.dev, pipe_id=0xFFFF)
        # Folded pipe
        self.folded_pipe = folded_pipe

        # Connect to BFRT server
        try:
            interface = gc.ClientInterface('{}:{}'.format(bfrt_ip, bfrt_port),
                                           client_id=0,
                                           device_id=self.dev)
        except RuntimeError as re:
            msg = re.args[0] % re.args[1]
            self.critical_error(msg)
        else:
            self.log.info('Connected to BFRT server {}:{}'.format(
                bfrt_ip, bfrt_port))

        try:
            interface.bind_pipeline_config(program)
        except gc.BfruntimeForwardingRpcException:
            self.critical_error('P4 program {} not found!'.format(program))

        try:
            # Get all tables for program
            self.bfrt_info = interface.bfrt_info_get(program)

            # Ports table
            self.ports = Ports(self.target, gc, self.bfrt_info)

            if self.folded_pipe:
                try:
                    # Enable loopback on front panel ports
                    loopback_ports = (
                        [64] +  # Pipe 0 CPU ethernet port
                        # Pipe 0: all 16 front-panel ports
                        # list(range(  0,  0+64,4)) +
                        # Pipe 1: all 16 front-panel ports
                        list(range(128, 128 + 64, 4)) +
                        # Pipe 2: all 16 front-panel ports
                        list(range(256, 256 + 64, 4)) +
                        # Pipe 3: all 16 front-panel ports
                        list(range(384, 384 + 64, 4)))
                    print(
                        'Setting {} front panel ports in loopback mode'.format(
                            len(loopback_ports)))
                    self.ports.set_loopback_mode(loopback_ports)

                    # Enable loopback on PktGen ports
                    pktgen_ports = [192, 448]

                    if not self.ports.get_loopback_mode_pktgen(pktgen_ports):
                        # Not all PktGen ports are in loopback mode

                        print(
                            '\nYou must \'remove\' the ports in the BF ucli:\n')
                        for p in pktgen_ports:
                            print('    bf-sde> dvm rmv_port 0 {}'.format(p))
                        input('\nPress Enter to continue...')

                        if not self.ports.set_loopback_mode_pktgen(
                                pktgen_ports):
                            self.critical_error(
                                'Failed setting front panel ports in loopback mode'
                            )

                        print('\nAdd the ports again:\n')
                        for p in pktgen_ports:
                            print(
                                '    bf-sde> dvm add_port 0 {} 100 0'.format(p))
                        input('\nPress Enter to continue...')

                        if not self.ports.get_loopback_mode_pktgen(
                                pktgen_ports):
                            self.critical_error(
                                'Front panel ports are not in loopback mode')

                except gc.BfruntimeReadWriteRpcException:
                    self.critical_error(
                        'Error while setting ports in loopback mode. \
                        If the switch has only 2 pipes, the folded pipeline cannot be enabled.'
                    )

            # Packet Replication Engine table
            self.pre = PRE(self.target, gc, self.bfrt_info)

            # Setup tables
            # Forwarder
            self.forwarder = Forwarder(self.target, gc, self.bfrt_info,
                                       self.all_ports_mgid)
            # ARP and ICMP responder
            self.arp_and_icmp = ARPandICMPResponder(self.target, gc,
                                                    self.bfrt_info)
            # Drop simulator
            self.drop_simulator = DropSimulator(
                self.target, gc, self.bfrt_info)
            # RDMA receiver
            self.rdma_receiver = RDMAReceiver(self.target, gc, self.bfrt_info)
            # UDP receiver
            self.udp_receiver = UDPReceiver(self.target, gc, self.bfrt_info)
            # Bitmap checker
            self.bitmap_checker = BitmapChecker(
                self.target, gc, self.bfrt_info)
            # Workers counter
            self.workers_counter = WorkersCounter(self.target, gc,
                                                  self.bfrt_info)
            # Exponents
            self.exponents = Exponents(self.target, gc, self.bfrt_info)
            # Processors
            self.processors = []
            for i in range(32):
                p = Processor(self.target, gc, self.bfrt_info, i)
                self.processors.append(p)
            # Next step selector
            self.next_step_selector = NextStepSelector(self.target, gc,
                                                       self.bfrt_info,
                                                       self.folded_pipe)
            # RDMA sender
            self.rdma_sender = RDMASender(self.target, gc, self.bfrt_info)
            # UDP sender
            self.udp_sender = UDPSender(self.target, gc, self.bfrt_info)

            # Add multicast group for flood
            self.pre.add_multicast_group(self.all_ports_mgid)

            # Enable ports
            success, error_msg = self.load_ports_file(ports_file)
            if not success:
                self.critical_error(error_msg)

            # Set switch addresses
            self.set_switch_mac_and_ip(switch_mac, switch_ip)

            # CLI setup
            self.cli = Cli()
            self.cli.setup(self, prompt='SwitchML', name='SwitchML controller')

            # Set up gRPC server
            self.grpc_server = GRPCServer(controller=self,
                                          ip='[::]',
                                          port=50099,
                                          folded_pipe=self.folded_pipe)

        except KeyboardInterrupt:
            self.critical_error('Stopping controller.')
        except Exception as e:
            self.log.exception(e)
            self.critical_error('Unexpected error. Stopping controller.')

    def load_ports_file(self, ports_file):
        ''' Load ports yaml file and enable front panel ports.

            Keyword arguments:
                ports_file -- yaml file name

            Returns:
                (success flag, None or error message)
        '''

        with open(ports_file) as f:
            yaml_ports = yaml.safe_load(f)

        for port, value in yaml_ports['ports'].items():

            re_match = front_panel_regex.match(port)
            if not re_match:
                return (False, 'Invalid port {}'.format(port))

            fp_port = int(re_match.group(1))
            fp_lane = int(re_match.group(2))

            # Convert all keys to lowercase
            value = {k.lower(): v for k, v in value.items()}

            if 'speed' in value:
                try:
                    speed = int(value['speed'].upper().replace('G',
                                                               '').strip())
                except ValueError:
                    return (False, 'Invalid speed for port {}'.format(port))

                if speed not in [10, 25, 40, 50, 100]:
                    return (
                        False,
                        'Port {} speed must be one of 10G,25G,40G,50G,100G'.
                        format(port))
            else:
                speed = 100

            if 'fec' in value:
                fec = value['fec'].lower().strip()
                if fec not in ['none', 'fc', 'rs']:
                    return (False,
                            'Port {} fec must be one of none, fc, rs'.
                            format(port))
            else:
                fec = 'none'

            if 'autoneg' in value:
                an = value['autoneg'].lower().strip()
                if an not in ['default', 'enable', 'disable']:
                    return (
                        False,
                        'Port {} autoneg must be one of default, enable, disable'
                        .format(port))
            else:
                an = 'default'

            # Add port
            success, error_msg = self.ports.add_port(
                fp_port, fp_lane, speed, fec, an)
            if not success:
                return (False, error_msg)

            success, dev_port = self.ports.get_dev_port(fp_port, fp_lane)
            if not success:
                return (False, dev_port)

            # Add port to flood multicast group
            rid = self.all_ports_initial_rid + dev_port
            success, error_msg = self.pre.add_multicast_node(
                self.all_ports_mgid, rid, dev_port)
            if not success:
                return (False, error_msg)

            self.multicast_groups[self.all_ports_mgid][rid] = dev_port

        for mac, port in yaml_ports['forwarding_table'].items():

            re_match = front_panel_regex.match(port)
            if not re_match:
                return (False, 'Invalid port {}'.format(port))

            fp_port = int(re_match.group(1))
            fp_lane = int(re_match.group(2))

            success, dev_port = self.ports.get_dev_port(fp_port, fp_lane)
            if not success:
                return (False, dev_port)

            # Add forwarding entry
            self.forwarder.add_entry(mac.upper(), dev_port)

        return (True, None)

    def set_switch_mac_and_ip(self, switch_mac, switch_ip):
        ''' Set switch MAC and IP '''
        self.switch_mac = switch_mac.upper()
        self.switch_ip = switch_ip

        self.arp_and_icmp.set_switch_mac_and_ip(
            self.switch_mac, self.switch_ip)
        self.rdma_receiver.set_switch_mac_and_ip(self.switch_mac,
                                                 self.switch_ip)
        self.udp_receiver.set_switch_mac_and_ip(
            self.switch_mac, self.switch_ip)
        self.rdma_sender.set_switch_mac_and_ip(self.switch_mac, self.switch_ip)
        self.udp_sender.set_switch_mac_and_ip(self.switch_mac, self.switch_ip)

    def get_switch_mac_and_ip(self):
        ''' Get switch MAC and IP '''
        return self.switch_mac, self.switch_ip

    def new_session(self, session_id, block_size):
        ''' Allocate a new session.

            Keyword arguments:
                session_id -- ID of the session
                block_size -- size of the requested block

            Returns:
                (success flag, base index or error message,
                actual size of the allocated block)
        '''

        if session_id >= 0x8000:
            self.log.error(
                "Client asked for session {} >= {}".format(session_id, 0x8000))
            return (False, "Maximum session ID is {}".format(0x8000), 0)
        if session_id in self.multicast_groups:
            self.log.error("Session {} already exists".format(session_id))
            return (False, "Session already exists", 0)

        success, base_index, actual_block_size = self.pool.allocate(block_size)
        if not success:
            self.log.error("Session {} Allocation error: {}".format(
                session_id, base_index))
            return (False, base_index, 0)

        self.session_to_base_index[session_id] = base_index

        # Add multicast group
        self.pre.add_multicast_group(session_id)
        self.multicast_groups[session_id] = {}

        self.log.debug("Session ID: {} Requested size: {} Allocated size: {}".format(
            session_id, block_size, actual_block_size))

        return success, base_index, block_size

    def destroy_session(self, session_id):
        ''' Destroy a session.

            Keyword arguments:
                session_id -- ID of the session

            Returns:
                (success flag, None or error message)
        '''

        if session_id not in self.multicast_groups or session_id not in self.session_to_base_index:
            self.log.error(
                "Destroy for non-existent session {}".format(session_id))
            return (False, "Session does not exist", 0)

        self.clear_rdma_workers(session_id)

        success = self.pool.deallocate(self.session_to_base_index[session_id])
        if not success:
            error_msg = "Session {} Deallocation error.".format(session_id)
            self.log.error(error_msg)
            return (False, error_msg)

        del self.session_to_base_index[session_id]
        return (True, None)

    def clear_multicast_group(self, session_id):
        ''' Remove multicast group and nodes for this session '''

        if session_id in self.multicast_groups:
            for node_id in self.multicast_groups[session_id]:
                self.pre.remove_multicast_node(node_id)
            self.pre.remove_multicast_group(session_id)

            del self.multicast_groups[session_id]

    def reset_workers(self):
        ''' Reset all workers state '''
        # TODO clear counters
        self.udp_receiver._clear()
        self.udp_sender.clear_udp_workers()
        self.rdma_receiver._clear()
        self.rdma_sender.clear_rdma_workers()
        self.bitmap_checker._clear()
        self.workers_counter._clear()
        self.exponents._clear()
        for p in self.processors:
            p._clear()

        for session_id in self.multicast_groups.copy():
            if session_id != self.all_ports_mgid:
                self.clear_multicast_group(session_id)

    def clear_rdma_workers(self, session_id):
        ''' Reset UDP workers state for this session '''
        # TODO selectively remove workers (RDMA or UDP) for
        # this session, clear RDMA sender/receiver counters,
        # clear bitmap/count/exponents/processors
        self.rdma_receiver._clear()
        self.rdma_sender.clear_rdma_workers()
        self.bitmap_checker._clear()
        self.workers_counter._clear()
        self.exponents._clear()
        for p in self.processors:
            p._clear()

        self.clear_multicast_group(session_id)

    def add_rdma_worker(self, session_id, worker_id, num_workers, worker_mac,
                        worker_ip, worker_rkey, packet_size, message_size,
                        qpns_and_psns):
        ''' Add SwitchML RDMA worker.

            Keyword arguments:
                session_id -- ID of the session
                worker_id -- worker rank
                num_workers -- number of workers in this session
                worker_mac -- worker MAC address
                worker_ip -- worker IP address
                worker_rkey -- worker remote key
                packet_size -- MTU for this session
                message_size -- RDMA message size for this session
                qpns_and_psns -- list of (QPn, initial psn) tuples

            Returns:
                (success flag, None or error message)
        '''
        if worker_id >= 32:
            error_msg = 'Worker ID {} too large; only 32 workers supported'.format(
                worker_id)
            self.log.error(error_msg)
            return (False, error_msg)

        if num_workers > 32:
            error_msg = 'Worker count {} too large; only 32 workers supported'.format(
                num_workers)
            self.log.error(error_msg)
            return (False, error_msg)

        # Get port for node
        success, dev_port = self.forwarder.get_dev_port(worker_mac)
        if not success:
            return (False, dev_port)

        if session_id not in self.multicast_groups:
            return (False, "No multicast group for session {}".format(session_id))

        # Add RDMA receiver/sender entries
        success, error_msg = self.rdma_receiver.add_rdma_worker(
            worker_id, worker_ip, self.switch_pkey, packet_size, num_workers,
            session_id)
        if not success:
            return (False, error_msg)

        self.rdma_sender.add_rdma_worker(worker_id, worker_mac, worker_ip,
                                         worker_rkey, packet_size, message_size,
                                         qpns_and_psns)

        self.worker_ip_to_session[worker_ip] = session_id

        if worker_id in self.multicast_groups[
                session_id] and self.multicast_groups[session_id][
                    worker_id] != dev_port:
            # Existing node with different port, remove it
            self.pre.remove_multicast_node(worker_id)
            del self.multicast_groups[session_id][worker_id]

        # Add multicast node if not present
        if worker_id not in self.multicast_groups[session_id]:
            # Add new node
            success, error_msg = self.pre.add_multicast_node(
                session_id, worker_id, dev_port)
            if not success:
                # TODO remove this RDMA worker
                return (False, error_msg)

            self.multicast_groups[session_id][worker_id] = dev_port

        self.log.info('Added RDMA worker {}:{} {}'.format(
            worker_id, worker_mac, worker_ip))

        return (True, None)

    def clear_udp_workers(self, session_id):
        ''' Reset UDP workers state for this session '''
        # TODO selectively remove workers (RDMA or UDP) for
        # this session, clear UDP sender/receiver counters,
        # clear bitmap/count/exponents/processors
        self.udp_receiver._clear()
        self.udp_sender.clear_udp_workers()
        self.bitmap_checker._clear()
        self.workers_counter._clear()
        self.exponents._clear()
        for p in self.processors:
            p._clear()

        # Multicast groups below 0x8000 are used for sessions
        # (the mgid is the session id)
        # TODO session_id = session_id % 0x8000
        session_id = 0  # Single session supported for now

        self.clear_multicast_group(session_id)

    def add_udp_worker(self, session_id, worker_id, num_workers, worker_mac,
                       worker_ip):
        ''' Add SwitchML UDP worker.

            Keyword arguments:
                session_id -- ID of the session
                worker_id -- worker rank
                num_workers -- number of workers in this session
                worker_mac -- worker MAC address
                worker_ip -- worker IP address

            Returns:
                (success flag, None or error message)
        '''
        # TODO session packet size
        if worker_id >= 32:
            error_msg = 'Worker ID {} too large; only 32 workers supported'.format(
                worker_id)
            self.log.error(error_msg)
            return (False, error_msg)

        if num_workers > 32:
            error_msg = 'Worker count {} too large; only 32 workers supported'.format(
                num_workers)
            self.log.error(error_msg)
            return (False, error_msg)

        # Get port for node
        success, dev_port = self.forwarder.get_dev_port(worker_mac)
        if not success:
            return (False, dev_port)

        # Multicast groups below 0x8000 are used for sessions
        # (the mgid is the session id)
        # TODO session_id = session_id % 0x8000
        session_id = 0  # Single session supported for now

        # Add UDP receiver/sender entries
        success, error_msg = self.udp_receiver.add_udp_worker(
            worker_id, worker_mac, worker_ip, self.udp_port, self.udp_mask,
            num_workers, session_id)
        if not success:
            return (False, error_msg)

        self.udp_sender.add_udp_worker(worker_id, worker_mac, worker_ip)

        if session_id not in self.multicast_groups:
            return (False, "No multicast group for session {}".format(session_id))

        if worker_id in self.multicast_groups[
                session_id] and self.multicast_groups[session_id][
                    worker_id] != dev_port:
            # Existing node with different port, remove it
            self.pre.remove_multicast_node(worker_id)
            del self.multicast_groups[session_id][worker_id]

        # Add multicast node if not present
        if worker_id not in self.multicast_groups[session_id]:
            # Add new node
            success, error_msg = self.pre.add_multicast_node(
                session_id, worker_id, dev_port)
            if not success:
                return (False, error_msg)

            self.multicast_groups[session_id][worker_id] = dev_port

        self.log.info('Added UDP worker {}:{} {}'.format(
            worker_id, worker_mac, worker_ip))

        return (True, None)

    def run(self):
        try:
            # Start listening for RPCs
            self.grpc_server.start()
            self.log.info('gRPC server started')

            # Start CLI
            self.cli.run()

            # Stop gRPC server
            self.grpc_server.stop()
            self.log.info('gRPC server stopped')

        except Exception as e:
            self.log.exception(e)

        self.log.info('Stopping controller')


if __name__ == '__main__':

    # Parse arguments
    argparser = argparse.ArgumentParser(description='SwitchML controller.')
    argparser.add_argument('--program',
                           type=str,
                           default='SwitchML',
                           help='P4 program name. Default: SwitchML')
    argparser.add_argument(
        '--bfrt-ip',
        type=str,
        default='127.0.0.1',
        help='Name/address of the BFRuntime server. Default: 127.0.0.1')
    argparser.add_argument('--bfrt-port',
                           type=int,
                           default=50052,
                           help='Port of the BFRuntime server. Default: 50052')
    argparser.add_argument(
        '--switch-mac',
        type=str,
        default='00:11:22:33:44:55',
        help='MAC address of the switch. Default: 00:11:22:33:44:55')
    argparser.add_argument('--switch-ip',
                           type=str,
                           default='10.0.0.254',
                           help='IP address of the switch. Default: 10.0.0.254')
    argparser.add_argument(
        '--ports',
        type=str,
        default='ports.yaml',
        help='YAML file describing machines connected to ports. Default: ports.yaml')
    argparser.add_argument(
        '--enable-folded-pipe',
        default=False,
        action='store_true',
        help='Enable the folded pipeline (requires a 4 pipes switch)')
    argparser.add_argument('--log-level',
                           default='INFO',
                           choices=['ERROR', 'WARNING', 'INFO', 'DEBUG'],
                           help='Default: INFO')

    args = argparser.parse_args()

    # Configure logging
    numeric_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_level, int):
        sys.exit('Invalid log level: {}'.format(args.log_level))

    logformat = '%(asctime)s - %(levelname)s - %(message)s'
    logging.basicConfig(filename='switchml.log',
                        filemode='w',
                        level=numeric_level,
                        format=logformat,
                        datefmt='%H:%M:%S')

    args.switch_mac = args.switch_mac.strip().upper()
    args.switch_ip = args.switch_ip.strip()
    args.bfrt_ip = args.bfrt_ip.strip()

    if not mac_address_regex.match(args.switch_mac):
        sys.exit('Invalid Switch MAC address')
    if not validate_ip(args.switch_ip):
        sys.exit('Invalid Switch IP address')
    if not validate_ip(args.bfrt_ip):
        sys.exit('Invalid BFRuntime server IP address')

    ctrl = SwitchML()
    ctrl.setup(args.program, args.switch_mac, args.switch_ip, args.bfrt_ip,
               args.bfrt_port, args.ports, args.enable_folded_pipe)

    # Start controller
    ctrl.run()

    # Flush log, stdout, stderr
    sys.stdout.flush()
    sys.stderr.flush()
    logging.shutdown()

    # Exit
    os.kill(os.getpid(), signal.SIGTERM)
