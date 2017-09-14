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
	struct sr_arpreq *req;
	/* arp hdr*/
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + etnet_hdr_size);
	if (ntohs(arp_header->ar_op) == arp_op_reply) {
		
	}
}

void handle_arpIncomingMessage(uint8_t *packet, struct sr_instance *sr, unsigned int len) {
	/* NOTE TO USE THE ETHERNET PROTOCOL ENUM FOR ARP messages AND also in ARP header to denote it's an ARP reply */	
	struct sr_if *currIface;
	struct sr_packet *pendingPkt;
	struct sr_arp_hdr *arp_hdr;
	struct sr_arpreq *req;
	
	/* Extract ARP header */
	arp_hdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
		
	/* Check to see if reply or request */
	if (arp_hdr->ar_op == arp_op_reply) {
		req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip); /* Sender's ip and mac */
		if (req){ 
			pendingPkt = req->packets;
			/* forward all packets from the req's queue on to that destination */
			while (pendingPkt != NULL) {
				/* CHECK: that it sends (FOR DEBUG PURPOSES) */
				/* Change ethernet addresses */
				struct sr_ethernet_hdr* pendingEtherHeader = (struct sr_ethernet_hdr*)pendingPkt->buf;
				memcpy(pendingEtherHeader->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN * sizeof(uint8_t));
				struct sr_if* pendingIface = sr_get_interface(sr, pendingPkt->iface);
				memcpy(pendingEtherHeader->ether_shost, pendingIface->addr, ETHER_ADDR_LEN * sizeof(uint8_t));
				
				sr_send_packet(sr, pendingPkt->buf, pendingPkt->len, pendingPkt->iface);
				pendingPkt = pendingPkt->next;
			}
			
			sr_arpreq_destroy(&(sr->cache), req);
		}
	} else {
		/* Go through linked list of interfaces, check their IP vs the destination IP of the ARP request packet */
		currIface = sr->if_list;
		while (currIface != NULL) {
			/* Check if packet is intended for us */
			if (currIface->ip == arp_hdr->ar_tip) {
				/* Create ARP reply packet (encapsulate in ethernet frame) and send to source of ARP request */
				struct sr_ethernet_hdr* ether_hdr = (struct sr_ethernet_hdr*)packet;
				/* The recipient MAC address will be the original sender's */
				memcpy(&ether_hdr->ether_dhost, &ether_hdr->ether_shost, ETHER_ADDR_LEN);
				/* The sending MAC address will be the interface's */
				memcpy(&ether_hdr->ether_shost, currIface->addr, ETHER_ADDR_LEN);
				arp_hdr->ar_op = arp_op_reply;
				arp_hdr->ar_tip = arp_hdr->ar_sip;
				arp_hdr->ar_sip = currIface->ip;
				memcpy(&arp_hdr->ar_tha, &arp_hdr->ar_sha, ETHER_ADDR_LEN);
				memcpy(&arp_hdr->ar_sha, currIface->addr, ETHER_ADDR_LEN);
				
				sr_send_packet(sr, packet, len, currIface->name);
				break;
			}
			currIface = currIface->next;
		}
		
	}
}

