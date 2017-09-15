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
  
    /*etnet hdr*/
    sr_ethernet_hdr_t* etnet_hdr;
    etnet_hdr = (sr_ethernet_hdr_t *)packet;
    
    /*etnet hdr size*/
    uint8_t* etnet_hdr_size = sizeof(sr_ethernet_hdr_t);
    
    /*ip hdr*/
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t *)(packet + etnet_hdr_size);
    
    /*etnet hdr size*/
    uint8_t* ip_hdr_size = sizeof(sr_ip_hdr_t);
	
    if (ntohs(etnet_hdr->ether_type) == ethertype_arp) {
	//handle_arpIncomingMessage(packet, sr, len); may be sr_handle_arp
	return 0;
    }
    else if (ntohs(etnet_hdr->ether_type) == ethertype_ip) {
	//handle_arpIncomingMessage(packet, sr, len); may be sr_handle_arp
	return 0;
    }
    
    if (len < etnet_hdr_size){
	/* Send ICMP Msg */
        return -1;
    }
    
    
}/* end sr_ForwardPacket */

void sr_handlearp(uint8_t *packet, 
		  struct sr_instance *sr, 
		  unsigned int len) 
{
	/* arp hdr*/
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + etnet_hdr_size);
	if (ntohs(arp_header->ar_op) == arp_op_request) {
		struct sr_arpreq *request = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
		
		/* Delete */
		if !(request){
			sr_arpreq_destroy(cache, request);
		}
		/* reply*/
		/*
			1) If ARP Request in Cache, add it anyway
			2) If ARP Request not in Cache, add it, remove from queue if was in queue
		*/
		
	}
}
