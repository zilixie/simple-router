/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
	/* REQUIRES */
	assert(sr);

	/* Initialize cache and cache cleanup thread */
	sr_arpcache_init(&(sr->cache));

	pthread_attr_init(&(sr->attr));
	pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_t thread;

	pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
	/* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	printf("*** -> Received packet of length %d \n",len);
    
	sr_ethernet_hdr_t *etnet_hdr;
	etnet_hdr = (sr_ethernet_hdr_t *)packet;
	int etnet_hdr_size = sizeof(sr_ethernet_hdr_t);

	/* Check length */
	if (len < etnet_hdr_size){
		/* Send ICMP Msg */
        	return;
    	}

	/* Receive ARP */
    	if (ntohs((*etnet_hdr).ether_type) == ethertype_arp) {
    		printf("Receive ARP \n\n");
		print_hdrs(packet, len);
		printf("\n\n");
    		handle_arp(sr, packet, len, interface);
		return;
    	}
	
	/* Receive IP */
    	else if (ntohs((*etnet_hdr).ether_type) == ethertype_ip) {
    		printf("Receive IP \n\n");
		print_hdrs(packet, len);
		printf("\n\n");
		handle_ip(sr, packet, len, interface);
		return;
    	}
    	/* fill in code here */

}/* end sr_ForwardPacket */


void handle_arp(struct sr_instance *sr,
		     uint8_t *packet/* lent */,
		     unsigned int len,
		     char *interface/* lent */)
{
	int etnet_hdr_size = sizeof(sr_ethernet_hdr_t);
	int ip_hdr_size = sizeof(sr_ip_hdr_t);

	if (len < etnet_hdr_size + ip_hdr_size){
		printf("Router received invalid length\n\n");
        	return;
	}
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + etnet_hdr_size);
	
	/*arp request*/
	if (ntohs(arp_hdr->ar_op) == arp_op_request){
		uint8_t *reply_pkt = (uint8_t *)malloc(ip_hdr_size + etnet_hdr_size);

		/*reply headers*/
		sr_ethernet_hdr_t *reply_etnet_hdr = (sr_ethernet_hdr_t *)reply_pkt;
		sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(reply_pkt + etnet_hdr_size);
		struct sr_if *interface_pt = sr_get_interface(sr, interface);

		reply_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
		reply_arp_hdr->ar_pro = arp_hdr->ar_pro;
		reply_arp_hdr->ar_hln = arp_hdr->ar_hln;
		reply_arp_hdr->ar_pln = arp_hdr->ar_pln;       
		reply_arp_hdr->ar_op = htons(arp_op_reply);

		replace_arp_hardware_addrs(reply_arp_hdr, interface_pt->addr, arp_hdr->ar_sha);
		reply_arp_hdr->ar_tip = arp_hdr->ar_sip;
		reply_arp_hdr->ar_sip = interface_pt->ip;
		replace_etnet_addrs(reply_etnet_hdr, interface_pt->addr, arp_hdr->ar_sha);
		reply_etnet_hdr->ether_type = htons(ethertype_arp);
		
		printf("Router send ARP reply\n\n");
		print_hdrs(reply_pkt, len);
		
		sr_send_packet(sr, reply_pkt, len, interface);
		free(reply_pkt);
		return;
	}
	/*arp reply*/
	if (ntohs(arp_hdr->ar_op) == arp_op_reply){
		struct sr_arpreq * request = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
		if (request != NULL) {
			struct sr_packet * current_pkt = request->packets;
			/*loop through all packet for this request*/
			while (current_pkt != NULL) {

				/*create ethernet header*/
				struct sr_ethernet_hdr* current_etnet_hdr = (struct sr_ethernet_hdr*)(current_pkt->buf);
				struct sr_if* current_interface_pt = sr_get_interface(sr, current_pkt->iface);

				replace_etnet_addrs(current_etnet_hdr, current_interface_pt->addr, arp_hdr->ar_sha);
				
				printf("Router send Packets waiting in queue\n\n");
				print_hdrs(current_pkt->buf, current_pkt->len);
				printf("\n\n %s \n\n\n", current_pkt->iface);
				sr_send_packet(sr, current_pkt->buf, current_pkt->len, current_pkt->iface);
				current_pkt = (*current_pkt).next;
			}
			sr_arpreq_destroy(&(sr->cache), request);
			return;
		}
	}
}

void handle_ip(struct sr_instance* sr,
				uint8_t * packet/* lent */,
				unsigned int len,
				char* interface/* lent */)
{
	int etnet_hdr_size = sizeof(sr_ethernet_hdr_t);
	int ip_hdr_size = sizeof(sr_ip_hdr_t);
	
	sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t *)(packet + etnet_hdr_size);

	if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
		printf("invalid datagram length\n");
		return;
	}

	if (!validate_ip_cksum(packet)) {
		printf("invalid ip packet cksum\n");
		return;	
	}

	/* Router is not the receiver*/
	if (!ip_in_sr_interface_list(sr, ip_hdr->ip_dst)) {

		ip_hdr->ip_ttl--;
		if (ip_hdr->ip_ttl == 0) {
			send_icmp_t11_pkt(sr, packet, interface, len);
		}
		ip_hdr->ip_sum = 0x0;
		ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr_size);

		struct sr_rt *rt_entry = rt_entry_lpm(sr, ip_hdr->ip_dst);

		if (rt_entry != NULL) {
			/* Outgoing interface*/
			struct sr_if *sender_interface_pt = sr_get_interface(sr, rt_entry->interface);

			/* Look up the cache to find arpentry*/
			struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, rt_entry->gw.s_addr);

			/*not found*/
			if (arp_entry == NULL) {
				/* Add to the arp queue */
				struct sr_arpreq * arp_req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, 
										  packet, len, sender_interface_pt->name);
				handle_arpreq(sr, arp_req);
				return;
			}

			else if (arp_entry != NULL){

				/*Construct ethernet header*/
				sr_ethernet_hdr_t * etnet_hdr;
				etnet_hdr = (sr_ethernet_hdr_t *)packet;

				replace_etnet_addrs(etnet_hdr, sender_interface_pt->addr, arp_entry->mac);
				sr_send_packet(sr, packet, len, sender_interface_pt->name);
				return;
			}
		}
		else {
			send_icmp_t3_pkt(sr,packet, interface, len, 3, 0);
			return;
		}
	/* Router is the receiver*/
	} else {
		printf("packet to the router\n");
		if(ip_hdr->ip_p == ip_protocol_icmp){
			printf("Router receives ICMP...\n");
			sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *) (packet + etnet_hdr_size + ip_hdr_size);
			if (icmp_hdr->icmp_type == (uint8_t) 8) {
				send_icmp_t0_pkt(sr, packet, interface,len, 0, 0);
			}

		}else{
			printf("Router receives TCP UDP...\n");
			send_icmp_t3_pkt(sr,packet, interface, len, 3, 3); 
		}
		return;
	}
}


void replace_etnet_addrs(sr_ethernet_hdr_t *etnet_hdr, uint8_t *src, uint8_t *dest) {
	memcpy(etnet_hdr->ether_shost, src, ETHER_ADDR_LEN);
	memcpy(etnet_hdr->ether_dhost, dest, ETHER_ADDR_LEN);
}

void replace_arp_hardware_addrs(sr_arp_hdr_t * arp_header, unsigned char * new_sha, unsigned char * new_tha) {
	memcpy(arp_header->ar_tha, new_tha, ETHER_ADDR_LEN);
	memcpy(arp_header->ar_sha, new_sha, ETHER_ADDR_LEN);
}


int validate_ip_cksum (uint8_t * packet) {
	int ip_hdr_size = sizeof(sr_ip_hdr_t);
	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	uint16_t hdr_cksum = ip_header->ip_sum;
	ip_header->ip_sum = (uint16_t) 0;
	if (hdr_cksum != cksum(ip_header, ip_hdr_size)) {
		ip_header->ip_sum = hdr_cksum;
		return 0;
	}
	ip_header->ip_sum = hdr_cksum;
	return 1;
}


struct sr_rt* rt_entry_lpm(struct sr_instance *sr, uint32_t ip_dst){
    	struct sr_rt* rt = sr->routing_table;
	struct sr_rt* longest_match = NULL;

    	uint32_t curr_mask = 0;
    
    	while(rt)
    	{
        	if(longest_match == NULL || rt->mask.s_addr > curr_mask)
        	{
        		uint32_t mask = rt->mask.s_addr;
            		if ((ip_dst & mask) == (rt->dest.s_addr & mask))
            		{
            			longest_match = rt;
                		curr_mask = rt->mask.s_addr;
            		} 
			rt = rt->next;
        	} else {
			rt = rt->next;
		}
    	}
    	return longest_match;
}


int ip_in_sr_interface_list(struct sr_instance* sr, uint32_t ip_dst){
	struct sr_if* interface_pt = sr->if_list;

	while(interface_pt){
		if (interface_pt->ip == ip_dst) {
			return 1;		
		}
		else{
			interface_pt = interface_pt->next;
		}
	}
	return 0;
}



void send_icmp_t11_pkt(struct sr_instance* sr, 
				uint8_t *packet, 
				char* interface,
				unsigned int len){

	int etnet_hdr_size = sizeof(sr_ethernet_hdr_t);
	int ip_hdr_size = sizeof(sr_ip_hdr_t);
	int icmp_t11_size = sizeof(struct sr_icmp_t11_hdr);

	/* received pkt*/
	sr_ip_hdr_t * received_ip_hdr = (sr_ip_hdr_t *)(packet + etnet_hdr_size);


	struct sr_if *sr_interface_pt = sr_get_interface(sr, interface);

	uint8_t *reply_pkt = (uint8_t *)malloc(icmp_t11_size + etnet_hdr_size + ip_hdr_size);
	memset(reply_pkt,0, icmp_t11_size + etnet_hdr_size + ip_hdr_size);

	sr_ethernet_hdr_t * reply_etnet_hdr = (sr_ethernet_hdr_t *) reply_pkt;
	sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (reply_pkt + etnet_hdr_size);
	sr_icmp_t11_hdr_t * icmp_hdr_t11 = (sr_icmp_t11_hdr_t *) (reply_pkt + etnet_hdr_size + ip_hdr_size);

	/*construct icmp t11 hdr*/
	icmp_hdr_t11->icmp_type = (uint8_t) 11;
	icmp_hdr_t11->unused = (uint32_t) 0;
	icmp_hdr_t11->icmp_sum = (uint16_t) 0;
	icmp_hdr_t11->icmp_code = (uint8_t) 0;
	memcpy(icmp_hdr_t11->data, received_ip_hdr, ICMP_DATA_SIZE);
	icmp_hdr_t11->icmp_sum = cksum(icmp_hdr_t11, icmp_t11_size);

	/*construct ip hdr*/

	ip_hdr->ip_hl = received_ip_hdr->ip_hl;
	ip_hdr->ip_v = received_ip_hdr->ip_v;
	ip_hdr->ip_tos = received_ip_hdr->ip_tos;
	ip_hdr->ip_off = received_ip_hdr->ip_off;
	ip_hdr->ip_ttl = INIT_TTL;
	ip_hdr->ip_p = ip_protocol_icmp;
	ip_hdr->ip_sum = 0x0;

	ip_hdr->ip_src = sr_interface_pt->ip;
	ip_hdr->ip_dst = received_ip_hdr->ip_src;


	ip_hdr->ip_len = ip_hdr_size + icmp_t11_size;
	ip_hdr->ip_id = 0;
	ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr_size);

	/*construct etnet hdr*/
	memcpy(reply_etnet_hdr->ether_shost, sr_interface_pt->addr, ETHER_ADDR_LEN); 
	memcpy(reply_etnet_hdr->ether_dhost, reply_etnet_hdr->ether_shost, ETHER_ADDR_LEN); 
	reply_etnet_hdr->ether_type = htons(ethertype_ip);

	int total_pkt_size = icmp_t11_size + etnet_hdr_size + ip_hdr_size;
	printf("\n\nsending t11 icmp\n\n");
	print_hdr_ip(reply_pkt);
	sr_send_packet(sr, reply_pkt, total_pkt_size, interface);
	free(reply_pkt);

}

void send_icmp_t0_pkt(struct sr_instance* sr, 
				uint8_t *packet, 
				char* interface,
				unsigned int len,
				int type, 
				int code){

	int etnet_hdr_size = sizeof(sr_ethernet_hdr_t);
	int ip_hdr_size = sizeof(sr_ip_hdr_t);

	/* received pkt*/
	sr_ethernet_hdr_t * received_etnet_hdr = (sr_ethernet_hdr_t *) packet;
	sr_ip_hdr_t * received_ip_hdr = (sr_ip_hdr_t *)(packet + etnet_hdr_size);

	struct sr_if *sr_interface_pt = sr_get_interface(sr, interface);
	uint8_t *reply_pkt = (uint8_t *)malloc(len);

	memcpy(reply_pkt, packet, len);
	sr_ethernet_hdr_t * reply_etnet_hdr = (sr_ethernet_hdr_t *) reply_pkt;
	sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (reply_pkt + etnet_hdr_size);
	sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *) (reply_pkt + etnet_hdr_size + ip_hdr_size);

	/*construct icmp hdr*/
	icmp_hdr->icmp_type = (uint8_t) type;
	icmp_hdr->icmp_sum = (uint16_t) 0;
	icmp_hdr->icmp_code = (uint8_t) code;
	icmp_hdr->icmp_sum = cksum(icmp_hdr, len - ip_hdr_size - etnet_hdr_size);

	/*construct ip hdr*/
	
	ip_hdr->ip_ttl = INIT_TTL;
	/*ip_hdr->ip_p = ip_protocol_icmp;*/
	ip_hdr->ip_sum = 0;

	ip_hdr->ip_src = received_ip_hdr->ip_dst;
	ip_hdr->ip_dst = received_ip_hdr->ip_src;

	ip_hdr->ip_id = 0;
	ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr_size);

	/*construct etnet hdr*/
	memcpy(reply_etnet_hdr->ether_shost, sr_interface_pt->addr, ETHER_ADDR_LEN); 
	memcpy(reply_etnet_hdr->ether_dhost, received_etnet_hdr->ether_shost, ETHER_ADDR_LEN); 
	reply_etnet_hdr->ether_type = htons(ethertype_ip);

	printf("\n\nsending icmp\n\n");
	print_hdrs(reply_pkt, len);
	sr_send_packet(sr, reply_pkt, len, interface);
	free(reply_pkt);

}


void send_icmp_t3_pkt(struct sr_instance* sr, 
				uint8_t *packet, 
				char* interface,
		      		unsigned int len,
				int type, 
				int code){

	int etnet_hdr_size = sizeof(sr_ethernet_hdr_t);
	int ip_hdr_size = sizeof(sr_ip_hdr_t);
	int t3_icmp_size = sizeof(sr_icmp_t3_hdr_t);

	/* received pkt*/
	sr_ethernet_hdr_t * received_etnet_hdr = (sr_ethernet_hdr_t *) packet;
	sr_ip_hdr_t * received_ip_hdr = (sr_ip_hdr_t *)(packet + etnet_hdr_size);

	struct sr_if *sr_interface_pt = sr_get_interface(sr, interface);
	uint8_t *reply_pkt = (uint8_t *)malloc(t3_icmp_size + etnet_hdr_size + ip_hdr_size);

	sr_ethernet_hdr_t * reply_etnet_hdr = (sr_ethernet_hdr_t *) reply_pkt;
	sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (reply_pkt + etnet_hdr_size);
	sr_icmp_t3_hdr_t * icmp_hdr_t3 = (sr_icmp_t3_hdr_t *) (reply_pkt + etnet_hdr_size + ip_hdr_size);

	/*construct icmp hdr*/
	icmp_hdr_t3->icmp_type = (uint8_t) type;
	icmp_hdr_t3->unused = 0;
	icmp_hdr_t3->icmp_sum = 0;
	icmp_hdr_t3->icmp_code = (uint8_t) code;
	icmp_hdr_t3->next_mtu = 0;
	memcpy(icmp_hdr_t3->data, received_ip_hdr, ICMP_DATA_SIZE);/**/
	icmp_hdr_t3->icmp_sum = cksum(icmp_hdr_t3, t3_icmp_size);


	/*construct ip hdr*/

	ip_hdr->ip_hl = received_ip_hdr->ip_hl;
	ip_hdr->ip_v = received_ip_hdr->ip_v;
	ip_hdr->ip_tos = received_ip_hdr->ip_tos;
	ip_hdr->ip_off = received_ip_hdr->ip_off;
	
	ip_hdr->ip_ttl = INIT_TTL;
	ip_hdr->ip_p = ip_protocol_icmp;
	ip_hdr->ip_sum = 0;
	
	/* wait to fix, code 0 */
	if (code == 0 || code == 1) {
		ip_hdr->ip_src = sr_interface_pt->ip;
	}
	else {
		ip_hdr->ip_src = received_ip_hdr->ip_dst;
	}
	
	
	ip_hdr->ip_dst = received_ip_hdr->ip_src;
	ip_hdr->ip_len = htons(ip_hdr_size + t3_icmp_size);
	ip_hdr->ip_id = 0;
	ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr_size);


	/*construct etnet hdr*/
	memcpy(reply_etnet_hdr->ether_shost, sr_interface_pt->addr, ETHER_ADDR_LEN); 
	memcpy(reply_etnet_hdr->ether_dhost, received_etnet_hdr->ether_shost, ETHER_ADDR_LEN); 
	reply_etnet_hdr->ether_type = htons(ethertype_ip);

	printf("\n\nsending t3 icmp\n\n");
	print_hdrs(reply_pkt, t3_icmp_size + etnet_hdr_size + ip_hdr_size);
	sr_send_packet(sr, reply_pkt, t3_icmp_size + etnet_hdr_size + ip_hdr_size, interface);
	free(reply_pkt);

}


