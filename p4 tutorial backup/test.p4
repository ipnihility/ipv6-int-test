/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<8>  UDP_PROTOCOL = 0x11;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV6 = 0x86DD;
const bit<16> TYPE_SRCROUTING = 0x1234;

const bit<8> PROTO_ICMP = 1;
const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_UDP = 17;
const bit<8> PROTO_SRV6 = 43;
const bit<8> PROTO_ICMPV6 = 58;
const bit<8> MRI_PROTOCOL = 150;

const bit<8> ICMP6_TYPE_NS = 135;
const bit<8> ICMP6_TYPE_NA = 136;
const bit<8> NDP_OPT_TARGET_LL_ADDR = 2;
const bit<48> IPV6_MCAST_01 = 0x33_33_00_00_00_01;
const bit<32> NDP_FLAG_ROUTER = 0x80000000;
const bit<32> NDP_FLAG_SOLICITED = 0x40000000;
const bit<32> NDP_FLAG_OVERRIDE = 0x20000000;

const bit<128> NDP_PREFIX = 0x0000_0000_0000_0000_0000_0000_0000_00ff;
const bit<32> MAX_PORT = 1 << 8;

#define MAX_HOPS 9

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<9>  egressSpec_t;
typedef bit<9>  ingressSpec_t;

typedef bit<8>  switchID_t;
typedef bit<16> qdepth_t;
typedef bit<48> ingress_timestamp_t;
typedef bit<48> egress_timestamp_t;
typedef bit<32> deq_timedelta_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header srcRoute_t {
    bit<1>    bos;
    bit<15>   port;
}

header ipv6_t{
    bit<4>    version;
    bit<8>    trafficClass;
    bit<20>   flowLabel;
    bit<16>   payLoadLen;
    bit<8>    nextHdr;
    bit<8>    hopLimit;
    bit<128>  srcAddr;
    bit<128>  dstAddr;
}

header bitmap_t {
    bit<1>  bit_swid;
    bit<1>  bit_in_port;
    bit<1>  bit_out_port;
    bit<1>  bit_in_qdepth;
    bit<1>  bit_out_qdepth;
    bit<1>  bit_in_time;
    bit<1>  bit_out_time;
    bit<1>  bit_queue_time;
    bit<8>  bit_reserve;
}

header int_count_t {
    bit<16>  length;
    bit<16>  count;
}

header switch1_t {
    switchID_t           swid;
	bit<8>               in_port;
	bit<8>               out_port;
	ingress_timestamp_t  in_time;
}

header switch2_t {
    switchID_t           swid;
	bit<8>               in_port;
	bit<8>               out_port;
	qdepth_t             in_qdepth;
	qdepth_t             out_qdepth;
	ingress_timestamp_t  in_time;
	egress_timestamp_t   out_time;
	deq_timedelta_t      queue_time;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16>   sport;
    bit<16>   dport;
    bit<16>   len;
    bit<16>   hdrChecksum;
}

header icmpv6_t {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
}

header ndp_t {
    bit<32> flags;
    bit<128> target_addr;
}

header ndp_option_t {
    bit<8> type;
    bit<8> length;
    bit<48> value;
}


struct flow_metadata_t {
    bit<32>              ingress_pkt_cnt;
	bit<32>              ingress_byte_cnt;
	bit<32>              ingress_drop_cnt;
	bit<32>              egress_pkt_cnt;
	bit<32>              egress_byte_cnt;
	bit<32>              egress_drop_cnt;
}

struct metadata {
    switchID_t        swid;
    bit<32>           ipv6_prefix;
    bit<32>           ndp_ipv6_suffix;
    bit<16>           remaining;
    flow_metadata_t   flow_metadata;
}

struct headers {
    ethernet_t             ethernet;
    srcRoute_t[MAX_HOPS]   srcRoutes;
    ipv6_t                 ipv6;
    bitmap_t               bitmap;
    int_count_t            int_count;
    switch1_t[MAX_HOPS]    swtraces1;
    switch2_t[MAX_HOPS]    swtraces2;
    tcp_t                  tcp;
    udp_t                  udp;
    icmpv6_t               icmpv6;
    ndp_t                  ndp;
    ndp_option_t           ndp_option;
}

error { IPHeaderTooShort }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV6: parse_ipv6;
            TYPE_SRCROUTING: parse_srcRouting;
            default: accept;
        }
    }

    state parse_srcRouting {
        packet.extract(hdr.srcRoutes.next);
        transition select(hdr.srcRoutes.last.bos) {
            1: parse_ipv6;
            default: parse_srcRouting;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            MRI_PROTOCOL: parse_bitmap;
            PROTO_ICMPV6: parse_icmpv6;
            default: accept;
        }
    }

    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        //local_metadata.icmp_type = hdr.icmpv6.type;
        transition select(hdr.icmpv6.type) {
            ICMP6_TYPE_NS: parse_ndp;
            ICMP6_TYPE_NA: parse_ndp;
            default: accept;
        }
    }

    state parse_ndp {
        packet.extract(hdr.ndp);
        transition parse_ndp_option;
    }

    state parse_ndp_option {
        packet.extract(hdr.ndp_option);
        transition accept;
    }

    state parse_bitmap {
        packet.extract(hdr.bitmap);
        transition select(hdr.bitmap.bit_queue_time) {
            1 : parse_int_count2;
            default: parse_int_count1;
        }
    }

    state parse_int_count1 {
        packet.extract(hdr.int_count);
        meta.remaining = hdr.int_count.count;
        transition select(meta.remaining) {
            0 : accept;
            default: parse_swtrace1;
        }
    }

    state parse_swtrace1 {
        packet.extract(hdr.swtraces1.next);
        meta.remaining = meta.remaining - 1;
        transition select(meta.remaining) {
            0 : accept;
            default: parse_swtrace1;
        }
    }

    state parse_int_count2 {
        packet.extract(hdr.int_count);
        meta.remaining = hdr.int_count.count;
        transition select(meta.remaining) {
            0 : accept;
            default: parse_swtrace2;
        }
    }

    state parse_swtrace2 {
        packet.extract(hdr.swtraces2.next);
        meta.remaining = meta.remaining - 1;
        transition select(meta.remaining) {
            0 : accept;
            default: parse_swtrace2;
        }
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    action drop() {
        mark_to_drop();
    }

    action ipv6_lpm_prepare() {
        meta.ipv6_prefix = (bit<32>)(hdr.ipv6.dstAddr >> 96);
    }

    action ndp_prepare() {
        meta.ndp_ipv6_suffix = (bit<32>)hdr.ndp.target_addr;
    }

    action ndp_ns_to_na(macAddr_t target_mac) {
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = target_mac;
        //hdr.ethernet.dstAddr = IPV6_MCAST_01;
        bit<128> host_ipv6_tmp = hdr.ipv6.srcAddr;
        hdr.ipv6.srcAddr = hdr.ndp.target_addr;
        hdr.ipv6.dstAddr = host_ipv6_tmp;
        hdr.icmpv6.type = ICMP6_TYPE_NA;
        hdr.ndp.flags = NDP_FLAG_ROUTER | NDP_FLAG_OVERRIDE;
        hdr.ndp_option.setValid();
        hdr.ndp_option.type = NDP_OPT_TARGET_LL_ADDR;
        hdr.ndp_option.length = 1;
        hdr.ndp_option.value = target_mac;
        hdr.ipv6.nextHdr = PROTO_ICMPV6;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        //local_metadata.skip_l2 = true;
    }

    table ndp_reply_table {
        key = {
            meta.ndp_ipv6_suffix: lpm;
        }
        actions = {
            ndp_ns_to_na;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    action ipv6_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
    }

    action srcRoute_nhop() {
        standard_metadata.egress_spec = (bit<9>)hdr.srcRoutes[0].port;
        hdr.srcRoutes.pop_front(1);
    }

    action srcRoute_finish() {
        hdr.ethernet.etherType = TYPE_IPV6;
    }

    action update_ipv6_ttl() {
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
    }

    table ipv6_lpm {
        key = {
            meta.ipv6_prefix: lpm;
        }
        actions = {
            ipv6_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    apply {
        if (hdr.srcRoutes[0].isValid()) {
            if (hdr.srcRoutes[0].bos == 1){
                srcRoute_finish();
            }
            srcRoute_nhop();
            update_ipv6_ttl();
        }
        else if(hdr.icmpv6.isValid() && hdr.icmpv6.type == ICMP6_TYPE_NS) {
            ndp_prepare();
            ndp_reply_table.apply();
        }
        else if (hdr.ipv6.isValid()) {
            ipv6_lpm_prepare();
            ipv6_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action add_swtrace1() {
        hdr.swtraces1.push_front(1);
        // According to the P4_16 spec, pushed elements are invalid, so we need
        // to call setValid(). Older bmv2 versions would mark the new header(s)
        // valid automatically (P4_14 behavior), but starting with version 1.11,
        // bmv2 conforms with the P4_16 spec.
        hdr.swtraces1[0].setValid();
        hdr.swtraces1[0].swid = (switchID_t)meta.swid;
        //hdr.swtraces1[0].swid = (switchID_t)0;
        hdr.swtraces1[0].in_port = (bit<8>)standard_metadata.ingress_port;
        hdr.swtraces1[0].out_port = (bit<8>)standard_metadata.egress_port;
        hdr.swtraces1[0].in_time = (ingress_timestamp_t)standard_metadata.ingress_global_timestamp;

        hdr.int_count.count = hdr.int_count.count + 1;
        hdr.int_count.length = hdr.int_count.length + 9;
        hdr.ipv6.payLoadLen = hdr.ipv6.payLoadLen + 9;
    }

    action add_swtrace2() {
        hdr.swtraces2.push_front(1);
        // According to the P4_16 spec, pushed elements are invalid, so we need
        // to call setValid(). Older bmv2 versions would mark the new header(s)
        // valid automatically (P4_14 behavior), but starting with version 1.11,
        // bmv2 conforms with the P4_16 spec.
        hdr.swtraces2[0].setValid();
        hdr.swtraces2[0].swid = (switchID_t)meta.swid;
        //hdr.swtraces2[0].swid = (switchID_t)0;
        hdr.swtraces2[0].in_port = (bit<8>)standard_metadata.ingress_port;
        hdr.swtraces2[0].out_port = (bit<8>)standard_metadata.egress_port;
        hdr.swtraces2[0].in_qdepth = (qdepth_t)standard_metadata.enq_qdepth;
        hdr.swtraces2[0].out_qdepth = (qdepth_t)standard_metadata.deq_qdepth;
        hdr.swtraces2[0].in_time = (ingress_timestamp_t)standard_metadata.ingress_global_timestamp;
        hdr.swtraces2[0].out_time = (egress_timestamp_t)standard_metadata.egress_global_timestamp;
        hdr.swtraces2[0].queue_time = (deq_timedelta_t)standard_metadata.deq_timedelta;

        hdr.int_count.count = hdr.int_count.count + 1;
        hdr.int_count.length = hdr.int_count.length + 23;
        hdr.ipv6.payLoadLen = hdr.ipv6.payLoadLen + 23;
    }

    action swtrace_prepare(switchID_t swid) {
        meta.swid = (switchID_t)swid;
    }

    table swtrace {
        actions = { 
	    swtrace_prepare;
	    NoAction; 
        }
        default_action = NoAction();
    }

    apply {
        if (hdr.bitmap.isValid()) {
            swtrace.apply();
            if (hdr.bitmap.bit_queue_time == 1) {
                add_swtrace2();
            }
            else {
                add_swtrace1();
            }
        }
    }

}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(hdr.ndp.isValid(),
            {
                hdr.ipv6.srcAddr,
                hdr.ipv6.dstAddr,
                hdr.ipv6.payLoadLen,
                8w0,
                hdr.ipv6.nextHdr,
                hdr.icmpv6.type,
                hdr.icmpv6.code,
                hdr.ndp.flags,
                hdr.ndp.target_addr,
                hdr.ndp_option.type,
                hdr.ndp_option.length,
                hdr.ndp_option.value
            },
            hdr.icmpv6.checksum,
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.srcRoutes);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.bitmap);
        packet.emit(hdr.int_count);
        packet.emit(hdr.swtraces1);
        packet.emit(hdr.swtraces2);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmpv6);
        packet.emit(hdr.ndp);
        packet.emit(hdr.ndp_option);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
