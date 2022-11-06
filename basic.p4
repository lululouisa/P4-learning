/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
   bit<16> label;
  bit<32> register_index;
  bit<32> register_index_inverse;
    bit<16> node_id;
    bit<16> feature_id;
  bit<1> isTrue;
  bit<32> syn_pkt;
	bit<1> first;
bit<32> srcip;
bit<32> dst2src_max_ps;
bit<32> src2dst_max_ps;
bit<1> direction;
bit<32> src2dst_pkt;
bit<32> dst2src_pkt;
bit<32> bidirectional_bytes;
bit<32> dst2src_bytes;
bit<32> src2dst_bytes;
bit<32> bidirectional_pkt;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t       tcp;
}

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
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
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
    
    register<bit<32>>(100) reg_syn_c;
	register<bit<32>>(100) reg_srcip;
	register<bit<32>>(100) reg_dst2src_max_ps;
	register<bit<32>>(100) reg_src2dst_max_ps;
	register<bit<32>>(100) reg_src2dst_pkt;
	register<bit<32>>(100) reg_dst2src_pkt;
	register<bit<32>>(100) reg_bidirectional_bytes;
 	register<bit<32>>(100) reg_dst2src_bytes;   
	register<bit<32>>(100) reg_src2dst_bytes;
	register<bit<32>>(100) reg_bidirectional_pkt;

	//test
	register<bit<1>>(3) reg_syn_value;
	register<bit<32>>(3) reg_packet_length;
	register<bit<9>>(3) reg_egress;
	register<bit<9>>(3) reg_output;
	register<bit<48>>(3) reg_time;

    action get_register_index() {//pkt index in flow
    //Get register position
    //pkt in same flow has same hash value, then with kette
    //hash(result, HashAlgorithms,(bit<n>0), {input keys}, (bit<16>state number))
		hash(meta.register_index, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr,
	                hdr.ipv4.dstAddr,
				    hdr.tcp.srcPort,
	                hdr.tcp.dstPort,
				    hdr.ipv4.protocol},
				    (bit<32>)8);//flow-based register saves per-flow state with maximal 65536
	}

    action get_register_index_inverse(){//to calculate bidirectional part
        hash(meta.register_index_inverse, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.dstAddr,
	                hdr.ipv4.srcAddr,
				    hdr.tcp.dstPort,
	                hdr.tcp.srcPort,
				    hdr.ipv4.protocol},
				    (bit<32>)8);

    }
    
    //initiate the register
    action init_register(){
        reg_syn_c.write(meta.register_index, 0);
	reg_srcip.write(meta.register_index,0);
	reg_dst2src_max_ps.write(meta.register_index,0);
	reg_src2dst_max_ps.write(meta.register_index, 0);
	reg_dst2src_pkt.write(meta.register_index, 0);
	reg_src2dst_pkt.write(meta.register_index, 0);
	reg_bidirectional_bytes.write(meta.register_index, 0);
	reg_dst2src_bytes.write(meta.register_index, 0);
	reg_src2dst_bytes.write(meta.register_index, 0);
	reg_bidirectional_pkt.write(meta.register_index, 0);
    }

    
    action syn_update(bit<32>  x){
        //meta.syn_pkt=(bit<32>)hdr.tcp.syn+meta.syn_pkt;//syn_pkt update
        meta.syn_pkt=(bit<32>)hdr.tcp.syn + meta.syn_pkt;
        reg_syn_c.write(( bit<32> ) x, meta.syn_pkt);
    }


    action drop() {
        mark_to_drop(standard_metadata);
    }

    action dst2src_max_ps_update(){
        meta.dst2src_max_ps=standard_metadata.packet_length;
        reg_dst2src_max_ps.write( meta.register_index, meta.dst2src_max_ps);//update the new max_ps
    }

    action src2dst_max_ps_update(){
        meta.src2dst_max_ps=standard_metadata.packet_length;
        reg_src2dst_max_ps.write(meta.register_index, meta.src2dst_max_ps);//update the new max_ps
        
    }
   action src2dst_pkt_update(){
	meta.src2dst_pkt= meta.src2dst_pkt +1 ;
	reg_src2dst_pkt.write(meta.register_index, meta.src2dst_pkt);
}
	  action dst2src_pkt_update(){
	meta.dst2src_pkt= meta.dst2src_pkt +1 ;
	reg_dst2src_pkt.write(meta.register_index, meta.dst2src_pkt);
}
	 action dst2src_bytes_update(){
	meta.dst2src_bytes= meta.dst2src_bytes +standard_metadata.packet_length ;
	reg_dst2src_bytes.write(meta.register_index, meta.dst2src_bytes);
}

	 action src2dst_bytes_update(){
	meta.src2dst_bytes= meta.src2dst_bytes +standard_metadata.packet_length ;
	reg_src2dst_bytes.write(meta.register_index, meta.src2dst_bytes);
}


    action Label (bit<16> node_id, bit<16> label) {
	meta.label = label;
	meta.node_id = node_id; //just for debugging otherwise not needed
    }

    action Hopping(bit<16> node_id, bit<16> f_id, bit<32> constant_th) {//here is defined threshold based on the decision tree
	//XX For rate comparisons 'th' is multiplied by time delta as division is not allowed

	bit<32> feature = 0;
	bit<16> f=f_id+1;
        bit<32> th=constant_th;//type error, contant_th can not be an assignment to calculate 

	if (f == 1) {
		
	    feature = meta.syn_pkt;
	}
	else if (f == 2) {
	  feature = meta.dst2src_max_ps;
	}
	//else if (f == 3) {
	   // feature = meta.bidirectional_bytes;
	   // th = th*3;//meanz=bytes/3--?th*3<bytes
	//}
	else if (f == 5){
	feature= meta.bidirectional_bytes;
	th=meta.bidirectional_pkt*th;}
   	 else if (f == 6){
   	    feature = meta.src2dst_max_ps;
    }

	if (feature <= th) meta.isTrue = 1;
	else meta.isTrue = 0;

	//meta.prevFeature = f - 1;
   	 meta.feature_id=f-1;
	meta.node_id = node_id;//same with the output side
    }

    action SetDirection() {

	meta.direction = 1;//fixed src -->h1
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

   table layer1{//table1: syn_c as feature to do condition: when 0 0 1, then implement Hopping with 1 1 2.5
        key={
	    meta.node_id: exact;
            meta.feature_id:exact;
		 meta.isTrue: exact;	 
        }
        actions={
            Hopping;//condition parameter 1 1 2--> update the node id and feature id and the isTrue
            Label;
            drop;
        }
        default_action = drop();}

    table layer2{
        key={
	    meta.node_id: exact;
            meta.feature_id:exact;
		    meta.isTrue: exact;	
        }
        actions={
            Label;
            drop;
            Hopping;
        }
        default_action = drop();
    }
    
    table layer3{
        key={
            meta.node_id: exact; 
	    meta.feature_id: exact;
		    meta.isTrue: exact;	
           
        }
        actions={
            drop;
            Label;
            Hopping;
        }
        default_action = drop();
    }
	 table layer4{
        key={
            meta.node_id: exact; 
	    meta.feature_id: exact;
		    meta.isTrue: exact;	
           
        }
        actions={
            drop;
            Label;
            Hopping;
        }
        default_action = drop();
	}

    table direction{
	    key = {
		standard_metadata.ingress_port: exact;    
	    }
	    actions = {
		NoAction;
		SetDirection;
	    }
	    size = 10;
	    default_action = NoAction();
	}

   
  

    table ipv4_classifier {
        key = {
            meta.label: exact;
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
}
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    apply {
	reg_syn_value.read(hdr.tcp_t.syn, 0);
        direction.apply();
	reg_packet_length.read(standard_metadata_t.packet_length, 0);
	reg_egress.read(standard_metadata.egress_spec, 0);
	reg_output.read(standard_metadata.egress_port, 0);
	reg_time.read(standard_metadata.ingress_global_timestamp, 0);

	reg_syn_value.write(0, hdr.tcp.syn);
	reg_packet_length.write(0, standard_metadata.packet_length);
	reg_egress.write(0, standard_metadata.egress_spec);
	reg_output.write(0, standard_metadata.egress_port);
	reg_time.write(0, standard_metadata.ingress_global_timestamp);
	
        if (hdr.ipv4.isValid()) {
	  if(meta.direction ==1){
	 	

                get_register_index();//with the index to read syn-pky count or other features
                

		reg_srcip.read(meta.srcip, meta.register_index);
		if (meta.srcip==0){
		meta.first=1;
		init_register();//is necessary?
		}
		
		if(meta.first==1){
		reg_srcip.write(meta.register_index, hdr.ipv4.srcAddr);
		meta.syn_pkt=0;
		}
		 
		reg_syn_c.read(meta.syn_pkt, meta.register_index);
		
		if(hdr.tcp.syn == 1){
			if(hdr.tcp.ack !=1 ){//seperate condition???
                syn_update(meta.register_index);//update the syn count
			}
		}

		//forward direction, only read no write
		reg_dst2src_max_ps.read(meta.dst2src_max_ps, meta.register_index);
               
		//feature 6
                reg_src2dst_max_ps.read(meta.src2dst_max_ps, meta.register_index);
                if(meta.src2dst_max_ps<=standard_metadata.packet_length){//empty register, meta.dst2src_max_ps==0< current length, update max_ps
                    src2dst_max_ps_update();}

		//feature bytes+pkt count -->for feature 4 & 5
		reg_src2dst_pkt.read(meta.src2dst_pkt, meta.register_index);
		src2dst_pkt_update();
		//direction 0 read
		reg_dst2src_pkt.read(meta.dst2src_pkt, meta.register_index);
		
		reg_src2dst_bytes.read(meta.src2dst_bytes, meta.register_index);
		src2dst_bytes_update();
		//direction 1  read
		reg_dst2src_bytes.read(meta.dst2src_pkt, meta.register_index);

		

	}
	else{//direction--0, backward
		get_register_index_inverse();//reverse flow pakcets
		meta.register_index= meta.register_index_inverse;
		reg_srcip.read(meta.srcip, meta.register_index);

		if (meta.srcip==0){
		meta.first=1;}
		
		if(meta.first==1){
		reg_srcip.write(meta.register_index_inverse, hdr.ipv4.srcAddr);
		}
		//feature bytes-->feature 4
		reg_dst2src_bytes.read(meta.dst2src_pkt, meta.register_index);
		dst2src_bytes_update();
		//direction 1 read
		reg_src2dst_bytes.read(meta.src2dst_bytes, meta.register_index);
	
		//feature pkt_count-->feature 5		
		reg_dst2src_pkt.read(meta.dst2src_pkt, meta.register_index);
		dst2src_pkt_update();
		//direction 1 read
		reg_src2dst_pkt.read(meta.src2dst_pkt, meta.register_index);
		
		reg_syn_c.read(meta.syn_pkt, meta.register_index);
		
			
		//feature 2		
		reg_dst2src_max_ps.read(meta.dst2src_max_ps, meta.register_index);
		if(meta.dst2src_max_ps<=standard_metadata.packet_length){//empty register, meta.dst2src_max_ps==0< current length, update max_ps
                    dst2src_max_ps_update();
		//direction 1 read only
                reg_src2dst_max_ps.read(meta.src2dst_max_ps, meta.register_index);

		}
	}	
		meta.bidirectional_pkt= meta.src2dst_pkt + meta.dst2src_pkt;
		meta.bidirectional_bytes=meta.src2dst_bytes+meta.dst2src_bytes;
		//reg_bidirectional_bytes.write(meta.register_index, meta.bidirectional_bytes);-->is necessary the register for bidirectional?
		

		meta.isTrue = 1;
                meta.feature_id=0;//the top one
		meta.node_id=0;
	layer1.apply();
		layer2.apply();
			layer3.apply();
				if(meta.label != 0 && meta.label != 1){//not set label	
				layer4.apply();}       
	 ipv4_classifier.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
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
