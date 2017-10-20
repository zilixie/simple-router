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

void sr_handlepacket(struct sr_instance *sr,
		     uint8_t *packet/* lent */,
		     unsigned int len,
		     char *interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);

    /*etnet hdr*/
    sr_ethernet_hdr_t *etnet_hdr;
    etnet_hdr = (sr_ethernet_hdr_t *)packet;
    /*etnet hdr size*/
    uint8_t *etnet_hdr_size = sizeof(sr_ethernet_hdr_t);
    memcpy(cpy_pkt, packet, len);

    /*ip hdr size*/
    uint8_t *ip_hdr_size = sizeof(sr_ip_hdr_t);

    if (len < etnet_hdr_size){
	/* Send ICMP Msg */
        return -1;
    }

    if (ntohs((*etnet_hdr).ether_type) == ethertype_arp) {
    	printf("receive ARP\n");
    	//handle_arp(sr, packet_copy, len, interface);
		return 0;
    }
    else if (ntohs((*etnet_hdr).ether_type) == ethertype_ip) {
    	printf("receive IP\n");


		//handle_ip
    	sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t *)(packet + etnet_hdr_size);
    	//valid checksum
    	ip_hdr->ip_sum = 0;
    	checksum = ip_hdr->ip_sum;
    	if (checksum != cksum(ip_hdr, ip_hdr->ip_len)) {
    		//drop packet
    		return -1;
    	}
    	time_to_live = ip_hdr->ip_ttl;
    	time_to_live--;
    	(*ip_hdr).ip_ttl = time_to_live;


    	if (ip_hdr->ip_ttl < 1) {
    		/* Send ICMP reply to sender type 11 code 0 */
    	}
    	checksum = cksum(ip_hdr, ip_hdr->ip_len);
    	ip_hdr->ip_sum = checksum;



    	//Recalculate checksum
		return 0;
    }



}/* end sr_ForwardPacket */


void sr_handle_ip_packet(struct sr_instance* sr,
				uint8_t * packet/* lent */,
				unsigned int len,
				char* interface/* lent */)
{
	sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t *)(packet + etnet_hdr_size);

	if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
		printf("invalid datagram length\n");
		return;
	}

	if (!validate_ip_cksum(packet)) {
		printf("invalid ip packet cksum\n");
		return;	
	}


	ip_hdr->ip_ttl--;

	if(ip_header->ip_ttl == 0) {
		/*send icmp time exceeded*/
		handle_icmp(sr, 11, 0, packet, len, interface); 
	} else {

		/* router is not the receiver*/
		if (ip_in_sr_interface_list(sr, ip_hdr->ip_dst)) {
			struct sr_rt *rt_entry = rt_entry_lpm(sr, ip_hdr->ip_dst);

			if (rt_entry != NULL) {
				//outgoing interface
				struct sr_if *sender_interface_pt = sr_get_interface(sr, rt_entry->interface);

				/* look up the cache to find arpentry*/
				struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, rt_entry->gw.s_addr);

				/*not found*/
				if (arp_entry == NULL) {
					/*add to the arp queue, and send a arp request*/
					struct sr_arpreq * arp_req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, out_if->name);
					handle_arpreq(sr, arp_req);
					return;
				}

				else if (arp_entry != NULL){

					/*prepare for ethernet header*/
					sr_ethernet_hdr_t * etnet_hdr;
					etnet_hdr = (sr_ethernet_hdr_t *)packet;

					replace_etnet_addrs(sender_interface_pt->addr, arp_entry->mac);
					sr_send_packet(sr, packet, len, sender_interface_pt->name);
				}
			}

		}



	struct sr_rt *rt_entry = rt_entry_lpm(sr, ip_hdr->ip_dst);

	if (ip_in_sr_interface_list(sr, ip_hdr->ip_dst)) {
		if(ip_hdr->ip_p == ip_protocol_icmp){
			printf("icmp\n");
			send_icmp_pkt(sr, len, packet, ICMP_ECHO_REPLY_CODE, 0, incoming_interface);
			/*process_icmp_packet(sr, len, packet, interface);		*/
		}

	}
}



void handle_arpreq(struct sr_instance *sr, struct sr_arpreq* arp_req){
	//struct sr_arpcache *cache = &(sr->cache);
	//struct sr_if *currIface;
	time_t now = time(0);
	time_t last_sent = arp_req->sent;
	uint32_t tiems_sent = arp_req->times_sent;
	
	struct sr_packet *pkt_pt;
	struct sr_arpcache *cache
	
	if (difftime(now, last_sent) > 1.0) {
		if (tiems_sent >= 5) {
			pkt_pt = arp_req->packets;			
			while (pkt_pt) {
				/* Send type 3 code 1 ICMP (Host Unreachable) */
				create_send_icmpMessage(sr, packet->buf, 3, 1, packet->iface);
				packet = packet->next;
			}
			/* Destroy the request afterwards */
			sr_arpreq_destroy(cache, req);
			
		} else {
			/* send arp request */
			uint8_t* broadcast_packet = malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr));
			unsigned int new_pkt_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
			
			
			struct sr_ethernet_hdr* new_ether_hdr = (struct sr_ethernet_hdr*)broadcast_packet;
			struct sr_arp_hdr* new_arp_hdr = (struct sr_arp_hdr*)(broadcast_packet + sizeof(struct sr_ethernet_hdr));
			memset(&new_ether_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
			new_ether_hdr->ether_type = ethertype_arp;
			
			currIface = sr->if_list;
			
			new_arp_hdr->ar_hrd = arp_hrd_ethernet;
			new_arp_hdr->ar_pro = ethertype_ip;
			new_arp_hdr->ar_hln = ETHER_ADDR_LEN;
			new_arp_hdr->ar_pln = 4; /* TODO: Find global constant if it exists */
			new_arp_hdr->ar_op = arp_op_request;
			memset(&new_arp_hdr->ar_tha, 0, ETHER_ADDR_LEN);
			new_arp_hdr->ar_tip = req->ip;
			
			
			while (currIface != NULL) {
				memcpy(&new_ether_hdr->ether_shost, currIface->addr, ETHER_ADDR_LEN);
				memcpy(&new_arp_hdr->ar_sha, currIface->addr, ETHER_ADDR_LEN);
				new_arp_hdr->ar_sip = currIface->ip;
				
				sr_send_packet(sr, broadcast_packet, new_pkt_len, currIface->name);
				
				currIface = currIface->next;
			}
			now = time(NULL);
			req->sent = now;
			req->times_sent++;
			free(broadcast_packet);
		}
	}
}




void handle_arp(struct sr_instance *sr,
		     uint8_t *packet/* lent */,
		     unsigned int len,
		     char *interface/* lent */)
{
	uint8_t *etnet_hdr_size = sizeof(sr_ethernet_hdr_t);
	uint8_t *ip_hdr_size = sizeof(sr_ip_hdr_t);

	if (len < etnet_hdr_size + ip_hdr_size){
	// Send ICMP Msg
        return -1;
    }

	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + etnet_hdr_size);

	if (ntohs(arp_hdr->ar_op) == arp_op_request){

		//reply headers
		sr_ethernet_hdr_t *reply_etnet_hdr = (sr_ethernet_hdr_t *)packet;
		sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(packet + etnet_hdr_size);

		struct sr_if *interface_pt = sr_get_interface(sr, interface);

    	reply_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
    	reply_arp_hdr->ar_pro = arp_hdr->ar_pro;
    	reply_arp_hdr->ar_hln = arp_hdr->ar_hln;
    	reply_arp_hdr->ar_pln = arp_hdr->ar_pln;       
		reply_arp_hdr->ar_op = htons(arp_op_reply);
		reply_arp_hdr->ar_tip = arp_hdr->ar_sip;
		reply_arp_hdr->ar_sip = interface_pt->ip;

		replace_arp_hardware_adds(reply_arp_hdr, interface_pt->addr, arp_hdr->ar_sha);
		replace_etnet_addrs(reply_etnet_hdr, interface_pt->addr, reply_etnet_hdr->ether_shost);
		sr_send_packet(sr, packet, len, interface);
	}

	//arp reply
	if (ntohs(arp_hdr->ar_op) == arp_op_reply){
		struct sr_arpreq * request = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
		if (request != NULL) {
			struct sr_packet * current_pkt = request->packets;
			/*loop through all packet for this request*/
			while (curr_pkt != NULL) {

				/*create ethernet header*/
				struct sr_ethernet_hdr* current_etnet_hdr = (struct sr_ethernet_hdr*)(current_pkt->buf);
				struct sr_if* current_interface_pt = sr_get_interface(sr, current_pkt->iface);

				replace_etnet_addrs(current_etnet_hdr, current_interface_pt->addr, arp_hdr->ar_sha)

				sr_send_packet(sr, current_pkt->buf, current_pkt->len, current_pkt->iface);
				current_pkt = (*current_pkt).next
			}
			sr_arpreq_destroy(&(sr->cache), request);
			return;
		}
	}
}


void replace_etnet_addrs(sr_ethernet_hdr_t *etnet_hdr, uint8_t *src, uint8_t *dest) {
	memcpy(etnet_hdr->ether_shost, src, ETHER_ADDR_LEN * sizeof(uint8_t));
	memcpy(etnet_hdr->ether_dhost, dest, ETHER_ADDR_LEN * sizeof(uint8_t));
}

void replace_arp_hardware_adds(sr_arp_hdr_t * arp_header, unsigned char * new_sha, unsigned char * new_tha) {
	memcpy(arp_header->ar_tha, new_tha, ETHER_ADDR_LEN);
	memcpy(arp_header->ar_sha, new_sha, ETHER_ADDR_LEN);
}

void construct_arp_hdr(sr_arp_hdr_t *arp_hdr) {

}

int validate_ip_cksum (uint8_t * packet) {
	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	uint16_t hdr_cksum = ip_header->ip_sum;
	ip_header->ip_sum = (uint16_t) 0;
	if (hdr_cksum != cksum(ip_header, ip_header->ip_len)) {
		ip_header->ip_sum = hdr_cksum;
		return 0;
	}
	ip_header->ip_sum = hdr_cksum;
	return 1;
}

struct sr_rt* rt_entry_lpm(struct sr_instance *sr, uint32_t ip_dst){
    struct sr_rt* routing_table = sr->routing_table;
	struct sr_rt* longest_match = NULL;

    uint32_t curr_mask = 0;
    
    while(routing_table)
    {
        if(longest_match = NULL || routing_table->mask.s_addr > curr_mask)
        {
        	uint32_t mask = routing_table->mask.s_addr;
            if ((ip_dst & mask) == (routing_table->dest.s_addr & mask))
            {
            	longest_match = routing_table;
                curr_mask = routing_table->mask.s_addr;
            } 
        }
        routing_table = routing_table->next;
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
	
struct sr_rt* get_Node_From_RoutingTable(struct sr_instance* sr, uint32_t ip){
	struct sr_rt *rt = sr->routing_table;

  while(rt) {
    if (rt->gw.s_addr == ip) {
      return rt;
    }
    rt = rt->next;
  }
return NULL;
}
