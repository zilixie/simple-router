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
	print_hdrs(packet, len);
    
	sr_ethernet_hdr_t *etnet_hdr;
	etnet_hdr = (sr_ethernet_hdr_t *)packet;
	int etnet_hdr_size = sizeof(sr_ethernet_hdr_t);
    
	if (len < etnet_hdr_size){
		/* Send ICMP Msg */
        	return;
    	}
    
    	if (ntohs((*etnet_hdr).ether_type) == ethertype_arp) {
    		printf("receive ARP\n");
    		handle_arp(sr, packet, len, interface);
		return;
    	}
    	else if (ntohs((*etnet_hdr).ether_type) == ethertype_ip) {
    		printf("receive IP\n");
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
		/*Send ICMP Msg*/
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

		print_hdrs(reply_pkt, len);
		sr_send_packet(sr, reply_pkt, len, interface);
	}
	/*arp reply*/
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
	memcpy(etnet_hdr->ether_shost, src, ETHER_ADDR_LEN);
	memcpy(etnet_hdr->ether_dhost, dest, ETHER_ADDR_LEN);
}

void replace_arp_hardware_addrs(sr_arp_hdr_t * arp_header, unsigned char * new_sha, unsigned char * new_tha) {
	memcpy(arp_header->ar_tha, new_tha, ETHER_ADDR_LEN);
	memcpy(arp_header->ar_sha, new_sha, ETHER_ADDR_LEN);
}

