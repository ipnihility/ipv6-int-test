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
	deq_timedelta_t        queue_time;
}

/*
header udp_t {
    bit<16>   sport;
    bit<16>   dport;
    bit<16>   len;
    bit<16>   hdrChecksum;
}
*/

struct flow_metadata_t {
    bit<32>              ingress_pkt_cnt;
	bit<32>              ingress_byte_cnt;
	bit<32>              ingress_drop_cnt;
	bit<32>              egress_pkt_cnt;
	bit<32>              egress_byte_cnt;
	bit<32>              egress_drop_cnt;
}

struct metadata {
    switchID_t swid;
    bit<32> ipv6_prefix;
    bit<16> remaining;
    flow_metadata_t flow_metadata;
}

struct headers {
    ethernet_t            ethernet;
    srcRoute_t[MAX_HOPS]  srcRoutes;
    ipv6_t                ipv6;
    bitmap_t               bitmap;
    int_count_t            int_count;
    switch1_t[MAX_HOPS]    swtraces1;
    switch2_t[MAX_HOPS]    swtraces2;
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
            default: accept;
        }
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

    action prepare() {
        meta.ipv6_prefix = (bit<32>)(hdr.ipv6.dstAddr >> 96);
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
        prepare();
        if (hdr.srcRoutes[0].isValid()) {
            if (hdr.srcRoutes[0].bos == 1){
                srcRoute_finish();
            }
            srcRoute_nhop();
            update_ipv6_ttl();
        }
        else if (hdr.ipv6.isValid()) {
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
