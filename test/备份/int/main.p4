/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <core.p4>
#include <v1model.p4>
//#include <p4d2model.p4>

#include "include/header.p4"
#include "include/parser.p4"
#include "include/checksum.p4"

#define CPU_CLONE_SESSION_ID 99


control IngressPipeImpl (inout parsed_headers_t hdr,
                         inout local_metadata_t local_metadata,
                         inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop();
    }

    /*
     * NDP reply table and actions.
     * Handles NDP router solicitation message and send router advertisement to the sender.
     */
    action ndp_ns_to_na(mac_addr_t target_mac) {
        hdr.ethernet.src_addr = target_mac;
        hdr.ethernet.dst_addr = IPV6_MCAST_01;
        bit<128> host_ipv6_tmp = hdr.ipv6.src_addr;
        hdr.ipv6.src_addr = hdr.ndp.target_addr;
        hdr.ipv6.dst_addr = host_ipv6_tmp;
        hdr.icmpv6.type = ICMP6_TYPE_NA;
        hdr.ndp.flags = NDP_FLAG_ROUTER | NDP_FLAG_OVERRIDE;
        hdr.ndp_option.setValid();
        hdr.ndp_option.type = NDP_OPT_TARGET_LL_ADDR;
        hdr.ndp_option.length = 1;
        hdr.ndp_option.value = target_mac;
        hdr.ipv6.next_hdr = PROTO_ICMPV6;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        local_metadata.skip_l2 = true;
    }

    direct_counter(CounterType.packets_and_bytes) ndp_reply_table_counter;
    table ndp_reply_table {
        key = {
            hdr.ndp.target_addr: exact;
        }
        actions = {
            ndp_ns_to_na;
        }
        counters = ndp_reply_table_counter;
    }

    /*
     * L2 exact table.
     * Matches the destination Ethernet address and set output port or do nothing.
     */

    action set_output_port(port_num_t port_num) {
        standard_metadata.egress_spec = port_num;
    }

    direct_counter(CounterType.packets_and_bytes) l2_exact_table_counter;
    table l2_exact_table {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = {
            set_output_port;
            @defaultonly NoAction;
        }
        const default_action = NoAction;
        counters = l2_exact_table_counter;
    }

    /*
     * L2 ternary table.
     * Handles broadcast address (FF:FF:FF:FF:FF:FF) and multicast address (33:33:*:*:*:*) and set multicast
     * group id for the packet.
     */
    action set_multicast_group(group_id_t gid) {
        standard_metadata.mcast_grp = gid;
        local_metadata.is_multicast = true;
    }

    direct_counter(CounterType.packets_and_bytes) l2_ternary_table_counter;
    table l2_ternary_table {
        key = {
            hdr.ethernet.dst_addr: ternary;
        }
        actions = {
            set_multicast_group;
            drop;
        }
        const default_action = drop;
        counters = l2_ternary_table_counter;
    }

    /*
     * L2 my station table.
     * Hit when Ethernet destination address is the device address.
     * This table won't do anything to the packet, but the pipeline will use the result (table.hit)
     * to decide how to process the packet.
     */
    direct_counter(CounterType.packets_and_bytes) l2_my_station_table_counter;
    table l2_my_station {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = {
            NoAction;
        }
        counters = l2_my_station_table_counter;
    }

    /*
     * L3 table.
     * Handles IPv6 routing. Pickup a next hop address according to hash of packet header fields (5-tuple).
     */
    action set_l2_next_hop(mac_addr_t dmac) {
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = dmac;
        hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
    }

    action_selector(HashAlgorithm.crc16, 32w64, 32w16) ecmp_selector;
    direct_counter(CounterType.packets_and_bytes) l3_table_counter;
    table l3_table {
      key = {
          hdr.ipv6.dst_addr: lpm;

          hdr.ipv6.dst_addr: selector;
          hdr.ipv6.src_addr: selector;
          hdr.ipv6.flow_label: selector;
          // the rest of the 5-tuple is optional per RFC6438
          local_metadata.ip_proto: selector;
          local_metadata.l4_src_port: selector;
          local_metadata.l4_dst_port: selector;
      }
      actions = {
          set_l2_next_hop;
      }
      implementation = ecmp_selector;
      counters = l3_table_counter;
    }

    /*
     * ACL table.
     * Clone the packet to the CPU (PacketIn) or drop the packet.
     */
    action clone_to_cpu() {
        clone3(CloneType.I2E, CPU_CLONE_SESSION_ID, standard_metadata);
    }

    direct_counter(CounterType.packets_and_bytes) acl_counter;
    table acl {
        key = {
            standard_metadata.ingress_port: ternary;
            hdr.ethernet.dst_addr: ternary;
            hdr.ethernet.src_addr: ternary;
            hdr.ethernet.ether_type: ternary;
            local_metadata.ip_proto: ternary;
            local_metadata.icmp_type: ternary;
            local_metadata.l4_src_port: ternary;
            local_metadata.l4_dst_port: ternary;
        }
        actions = {
            clone_to_cpu;
            drop;
        }
        counters = acl_counter;
    }



    action srcRoute_nhop() {
        standard_metadata.egress_spec = (bit<9>)hdr.srcRoutes[0].port;
        hdr.srcRoutes.pop_front(1);
    }

    action srcRoute_finish() {
        hdr.ethernet.ether_type = ETHERTYPE_IPV6;
    }

    action update_ipv6_ttl() {
        hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
    }


    apply {
        if (hdr.packet_out.isValid()) {
            standard_metadata.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
            exit;
        }
        if (hdr.icmpv6.isValid() && hdr.icmpv6.type == ICMP6_TYPE_NS) {
            ndp_reply_table.apply();
        }

        if (hdr.srcRoutes[0].isValid()) {
            if (hdr.srcRoutes[0].bos == 1){
                srcRoute_finish();
            }
            srcRoute_nhop();
            update_ipv6_ttl();
        }
        else if (l2_my_station.apply().hit) {
            if (hdr.ipv6.isValid()) {
                l3_table.apply();
                if(hdr.ipv6.hop_limit == 0) {
                    drop();
                }
            }
        }
        if (!local_metadata.skip_l2 && standard_metadata.drop != 1w1) {
            if (!l2_exact_table.apply().hit) {
                l2_ternary_table.apply();
            }
        }

        acl.apply();
    }
}

control EgressPipeImpl (inout parsed_headers_t hdr,
                        inout local_metadata_t local_metadata,
                        inout standard_metadata_t standard_metadata) {

    action add_swtrace() {
        hdr.swtraces.push_front(1);
        // According to the P4_16 spec, pushed elements are invalid, so we need
        // to call setValid(). Older bmv2 versions would mark the new header(s)
        // valid automatically (P4_14 behavior), but starting with version 1.11,
        // bmv2 conforms with the P4_16 spec.
        hdr.swtraces[0].setValid();
        //hdr.swtraces[0].swid = (switchID_t)swid;
        hdr.swtraces[0].swid = (switchID_t)0;
        hdr.swtraces[0].in_port = (bit<8>)standard_metadata.ingress_port;
        hdr.swtraces[0].out_port = (bit<8>)standard_metadata.egress_port;
        hdr.swtraces[0].in_qdepth = (qdepth_t)standard_metadata.enq_qdepth;
        hdr.swtraces[0].out_qdepth = (qdepth_t)standard_metadata.deq_qdepth;
        hdr.swtraces[0].in_time = (ingress_timestamp_t)standard_metadata.ingress_global_timestamp;
        hdr.swtraces[0].queue_time = (egress_timestamp_t)standard_metadata.egress_global_timestamp;
        hdr.swtraces[0].ingress_pkt_cnt = 0;
        hdr.swtraces[0].ingress_byte_cnt = 0;
        hdr.swtraces[0].ingress_drop_cnt = 0;
        hdr.swtraces[0].egress_pkt_cnt = 0;
        hdr.swtraces[0].egress_byte_cnt = 0;
        hdr.swtraces[0].egress_drop_cnt = 0;

        /*hdr.swtraces[0].ingress_pkt_cnt = local_metadata.flow_metadata.ingress_pkt_cnt;
        hdr.swtraces[0].ingress_byte_cnt = local_metadata.flow_metadata.ingress_byte_cnt;
        hdr.swtraces[0].ingress_drop_cnt = local_metadata.flow_metadata.ingress_drop_cnt;
        hdr.swtraces[0].egress_pkt_cnt = local_metadata.flow_metadata.egress_pkt_cnt;
        hdr.swtraces[0].egress_byte_cnt = local_metadata.flow_metadata.egress_byte_cnt;
        hdr.swtraces[0].egress_drop_cnt = local_metadata.flow_metadata.egress_drop_cnt;*/

        hdr.mri.count = hdr.mri.count + 1;
        hdr.mri.length = hdr.mri.length + 17 + 24;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 17 + 24;
        /*hdr.swtraces[0].bos = (bit<8>)(hdr.mri.count > 1 ? (bit<8>)0 : (bit<8>)1);*/
    
    }

    apply {
        if (hdr.mri.isValid()) {
            add_swtrace();
        }

        // TODO EXERCISE 1
        // Implement logic such that if the packet is to be forwarded to the CPU
        // port, i.e. we requested a packet-in in the ingress pipeline
        // (standard_metadata.egress_port == CPU_PORT):
        // 1. Set packet_in header as valid
        // 2. Set the packet_in.ingress_port field to the original packet's
        //    ingress port (standard_metadata.ingress_port).
        // ---- START SOLUTION ----
        if (standard_metadata.egress_port == CPU_PORT) {
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = standard_metadata.ingress_port;
        }
        // ---- END SOLUTION ----

        if (local_metadata.is_multicast == true
             && standard_metadata.ingress_port == standard_metadata.egress_port) {
            mark_to_drop();
        }
    }
}

V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressPipeImpl(),
    EgressPipeImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;
