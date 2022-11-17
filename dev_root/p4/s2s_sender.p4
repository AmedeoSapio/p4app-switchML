/*
  Copyright 2021 Intel-KAUST-Microsoft

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#ifndef _S2S_SENDER_
#define _S2S_SENDER_

control S2SSender(
    inout egress_metadata_t eg_md,
    in egress_intrinsic_metadata_t eg_intr_md,
    inout header_t hdr) {

    DirectCounter<counter_t>(CounterType_t.PACKETS_AND_BYTES) send_counter;

    action set_switch_mac_and_ip(mac_addr_t switch_mac, mac_addr_t next_switch_mac) {

        hdr.ethernet.setValid();

        // Set switch addresses
        hdr.ethernet.src_addr = switch_mac;
        // Set to destination node
        hdr.ethernet.dst_addr = next_switch_mac;
        hdr.ethernet.ether_type = ETHERTYPE_SWITCHML;

        // Disable IPv4 checksum
        eg_md.update_ipv4_checksum = false;

        // Disable UDP checksum for now
        hdr.udp.checksum = 0;

        hdr.s2s.setValid();
        hdr.s2s.packet_type = packet_type_t.CONSUME0;
        //hdr.s2s.transport_type = 0b1;
        hdr.s2s.pool_index = eg_md.switchml_md.pool_index;
        hdr.s2s.tsi = eg_md.switchml_md.tsi;
//TODO        hdr.s2s.worker_id;
//TODO        hdr.s2s.ingress_port; //9 //this can be removed with learning

        // Exponents
        hdr.exponents.setValid();
        hdr.exponents.e0 = eg_md.switchml_md.e0;
        hdr.exponents.e1 = eg_md.switchml_md.e1;

        hdr.s2s_rdma.setValid();
        hdr.s2s_rdma.msg_id = eg_md.switchml_md.msg_id;
        hdr.s2s_rdma.first_packet = eg_md.switchml_md.first_packet;
        hdr.s2s_rdma.last_packet = eg_md.switchml_md.last_packet;
        hdr.s2s_rdma.rdma_addr = eg_md.switchml_rdma_md.rdma_addr;

        // Count send
        send_counter.count();
    }

    table next_switch {
        actions = { @defaultonly set_switch_mac_and_ip; }
        size = 1;
        counters = send_counter;
    }

    apply {        
        next_switch.apply();
    }
}

#endif /* _UDP_SENDER_ */

