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
    	//handle_arp(sr, packet_copy, len, interface);
		return 0;
    }
    else if (ntohs((*etnet_hdr).ether_type) == ethertype_ip) {
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
		//look at cache see if exists
		struct sr_arpreq *request = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

		//insert and delete
		if !(request){
			sr_arpreq_destroy(cache, request);
		}
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

		replace_arp_hardware_adds(arp_hdr, interface_pt->addr, arp_hdr->ar_sha);
		replace_etnet_addrs(ethernet_header, interface_pt->addr, ethernet_header->ether_shost);
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

				//memmove(reply_etnet_hdr->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN * sizeof(uint8_t));
				//memmove(reply_etnet_hdr->ether_shost, reply_if->addr, ETHER_ADDR_LEN * sizeof(uint8_t));
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
