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

import grpc
import ipaddress

import switchml_pb2
import switchml_pb2_grpc

from concurrent import futures

from common import PacketSize


class GRPCServer(switchml_pb2_grpc.SessionServicer):

    def __init__(self,
                 controller=None,
                 ip='[::]',
                 port=50099,
                 folded_pipe=False):

        self.log = logging.getLogger(__name__)

        self._ctrl = controller
        self._folded_pipe = folded_pipe

        # Run gRPC server in a dedicated thread
        # limit concurrency to 1 to avoid synchronization problems in the BFRT interface
        self._executor = futures.ThreadPoolExecutor(max_workers=1)
        self._server = grpc.server(self._executor)
        switchml_pb2_grpc.add_SessionServicer_to_server(self, self._server)
        self._server.add_insecure_port('{}:{}'.format(ip, port))

    def start(self):
        ''' Start the gRPC server '''
        self._server.start()

    def stop(self):
        ''' Stop the gRPC server '''

        # Stop the gRPC server with a 5 seconds grace period before aborting RPCs
        self._server.stop(5).wait()

        # Free executor resources
        self._executor.shutdown()

    def RdmaCreateSession(self, request, context):
        ''' RDMA session setup '''

        result = switchml_pb2.Result(code=0, message="Success")

        if not self._ctrl:
            # This is a test, return the received parameters
            return switchml_pb2.RdmaCreateSessionResponse(
                pool_size=request.pool_size,
                base_index=0,
                packet_size=request.packet_size,
                message_size=request.message_size,
                switch=request.workers,
                error=result)

        # Get switch addresses
        switch_mac, switch_ipv4 = self._ctrl.get_switch_mac_and_ip()
        switch_mac = int(switch_mac.replace(':', ''), 16)
        switch_ipv4 = int(ipaddress.ip_address(switch_ipv4))

        session_id = request.session_id.id
        block_size = request.pool_size

        # Allocate new session
        success, base_index, block_size = self._ctrl.new_session(
            session_id, block_size)

        if not success:
            self.log.error(base_index)
            result.code = 1
            result.message = base_index
            return switchml_pb2.RdmaCreateSessionResponse(error=result)

        num_workers = len(request.workers)

        packet_size = PacketSize(request.packet_size)
        if not self._folded_pipe and packet_size == PacketSize.MTU_1024:
            self.log.warning(
                "Processing 1024B per packet requires a folded pipeline. Using 256B payload."
            )
            packet_size = PacketSize.MTU_256

        message_size = request.message_size
        switch = []

        self.log.debug(
            '# RDMA:\n Session ID: {}\n Num workers: {}\n Base index: {}\n Block size: {}B\n Pkt size: {}B\n Msg size: {}B\n'
            .format(session_id, num_workers, base_index, block_size,
                    str(packet_size).split('.')[1][4:], message_size))

        for worker in request.workers:

            # Convert MAC to string
            mac_hex = '{:012X}'.format(worker.mac)
            mac_str = ':'.join(
                mac_hex[i:i + 2] for i in range(0, len(mac_hex), 2))

            # Convert IP to string
            ipv4_str = str(ipaddress.ip_address(worker.ipv4))

            # Add new worker
            success, error_msg = self._ctrl.add_rdma_worker(
                session_id, worker.rank, num_workers, mac_str, ipv4_str,
                worker.rkey, int(packet_size), message_size,
                zip(worker.qpns, worker.psns))
            if not success:
                self.log.error(error_msg)
                result.code = 1
                result.message = error_msg
                return switchml_pb2.RdmaCreateSessionResponse(error=result)

            # Mirror this worker's rkey, since the switch doesn't care
            switch_rkey = worker.rkey

            # Switch QPNs are used for two purposes:
            # 1. Indexing into the PSN registers
            # 2. Differentiating between processes running on the same server
            #
            # Additionally, there are two restrictions:
            #
            # 1. In order to make debugging easier, we should
            # avoid QPN 0 (sometimes used for management) and QPN
            # 0xffffff (sometimes used for multicast) because
            # Wireshark decodes them improperly, even when the NIC
            # treats them properly.
            #
            # 2. Due to the way the switch sends aggregated
            # packets that are part of a message, only one message
            # should be in flight at a time on a given QPN to
            # avoid reordering packets. The clients will take care
            # of this as long as we give them as many QPNs as they
            # give us.
            #
            # Thus, we construct QPNs as follows.
            # - Bit 23 is always 1. This ensures we avoid QPN 0.
            # - Bits 22 through 16 are the rank of the
            #   client. Since we only support 32 clients per
            #   aggregation in the current design, we will never
            #   use QPN 0xffffff.
            # - Bits 15 through 0 are just the index of the queue;
            #   if 4 queues are requested, these bits will
            #   represent 0, 1, 2, and 3.
            #
            # So if a client with rank 3 sends us a request with 4
            # QPNs, we will reply with QPNs 0x830000, 0x830001,
            # 0x830002, and 0x830003.

            switch_qpns = [
                0x800000 | (worker.rank << 16) | i
                for i, _ in enumerate(worker.qpns)
            ]

            # Initial PSNs don't matter; they're overwritten by each _FIRST or _ONLY packet.
            switch_psns = [i for i, _ in enumerate(worker.qpns)]

            switch.append(
                switchml_pb2.RdmaEndpoint(rank=worker.rank,
                                          mac=switch_mac,
                                          ipv4=switch_ipv4,
                                          rkey=switch_rkey,
                                          qpns=switch_qpns,
                                          psns=switch_psns))

            self.log.debug(
                '  Worker {}:\n MAC: {}\n IPv4: {}\n Rkey: {}\n QPs: {}\n PSNs: {}\n'
                .format(worker.rank, mac_str, ipv4_str, worker.rkey,
                        worker.qpns, worker.psns))

        return switchml_pb2.RdmaCreateSessionResponse(
            pool_size=block_size,
            base_index=base_index,
            packet_size=int(packet_size),
            message_size=message_size,
            switch=switch,
            error=result)

    def DestroySession(self, request, context):
        ''' Destroy RDMA session '''

        result = switchml_pb2.Error(code=0, message="Success")

        self.log.debug('# RDMA:\n Removed session ID: {}'.format(request.id))

        if self._ctrl:
            # This is not a test
            success, error_msg = self._ctrl.destroy_session(request.id)
            if not success:
                self.log.error(error_msg)
                result.code = 1
                result.message = error_msg

        return result


# def UdpSession(self, request, context):
#    ''' UDP session setup '''
#
#    # Convert MAC to string
#    mac_hex = '{:012X}'.format(request.mac)
#    mac_str = ':'.join(mac_hex[i:i + 2] for i in range(0, len(mac_hex), 2))
#
#    # Convert IP to string
#    ipv4_str = str(ipaddress.ip_address(request.ipv4))
#
#    self.log.debug(
#        '# UDP:\n Session ID: {}\n Rank: {}\n Num workers: {}\n MAC: {}\n'
#        ' IPv4: {}\n Pkt size: {}\n'.format(request.session_id, request.rank,
#                                          request.num_workers, mac_str,
#                                          ipv4_str, request.packet_size))
#
#    if not self.ctrl:
#        # This is a test, return the received parameters
#        return switchml_pb2.UdpSessionResponse(
#            session_id=request.session_id,
#            mac=request.mac,
#            ipv4=request.ipv4)
#
#    if request.rank == 0:
#        # This is the first message, clear out old workers state
#        self.ctrl.clear_udp_workers(request.session_id)
#
#    # Add new worker
#    success, error_msg = self.ctrl.add_udp_worker(request.session_id,
#                                                  request.rank,
#                                                  request.num_workers,
#                                                  mac_str, ipv4_str)
#    if not success:
#        self.log.error(error_msg)
#        #TODO return error message
#        return switchml_pb2.UdpSessionResponse(session_id=0, mac=0, ipv4=0)
#
#    # Get switch addresses
#    switch_mac, switch_ipv4 = self.ctrl.get_switch_mac_and_ip()
#    switch_mac = int(switch_mac.replace(':', ''), 16)
#    switch_ipv4 = int(ipaddress.ip_address(switch_ipv4))
#
#    return switchml_pb2.UdpSessionResponse(session_id=request.session_id,
#                                           mac=switch_mac,
#                                           ipv4=switch_ipv4)

if __name__ == '__main__':

    # Set up gRPC server
    grpc_server = GRPCServer()

    # Start gRPC server (without a controller)
    grpc_server.start()

    try:
        # Busy wait
        while True:
            pass
    except KeyboardInterrupt:
        print('\nExiting...')
    finally:
        # Stop gRPC server
        grpc_server.stop()

        # Flush log
        logging.shutdown()
