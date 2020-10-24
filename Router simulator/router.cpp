#include <bits/stdc++.h>
#include <vector>
#include <fstream> 
#include <iostream>
#include "skel.h"

using namespace std;

extern int interfaces[ROUTER_NUM_INTERFACES];
const u_char BROADCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; 

vector<struct route_table_entry> rtable;
int rtable_size;

vector<struct arp_entry> arp_table;
int arp_table_len;

queue<packet> packet_queue;


bool comparator(struct route_table_entry entry1, struct route_table_entry entry2) {
	if (entry1.prefix != entry2.prefix) {
		return (entry1.prefix < entry2.prefix);
	} else {
		return (entry1.mask < entry2.mask);
	}
}

int read_rtable(string filename) {
	struct route_table_entry entry;
	ifstream f (filename);
	string prefix, hop, mask; 
	int interface;

	while (f >> prefix) {
		entry.prefix = inet_addr(prefix.c_str());

		f >> hop; 
		entry.next_hop = inet_addr(hop.c_str());

		f >> mask;
		entry.mask = inet_addr(mask.c_str());

		f >> interface;
		entry.interface = interface;

		rtable.push_back(entry);
	}

	sort(rtable.begin(), rtable.end(), comparator);

	f.close();
	return rtable.size();
}

struct route_table_entry *get_best_route(__u32 dest_ip) {
	struct route_table_entry* match = NULL; 

	int left = 0;
	int right = rtable.size() - 1;

	while (left <= right) {
		int mid = (left + right) / 2;

		if (rtable[mid].prefix  == (dest_ip & rtable[mid].mask)) {
			while (rtable[mid].prefix == (dest_ip & rtable[mid].mask)) {
				match = &rtable[mid];
				mid++;
			}
			return match;
		}
		
		if (rtable[mid].prefix < (dest_ip & rtable[mid].mask)) {
			left = mid + 1;
		}

		if (rtable[mid].prefix > (dest_ip & rtable[mid].mask)) {
			right = mid - 1;
		}
	}

	return match; 
}


struct arp_entry *get_arp_entry(__u32 ip) {
    struct arp_entry * match = NULL;

    for (unsigned i = 0; i < arp_table.size(); i++) {
    	if (arp_table[i].ip == ip) {
    		match = &arp_table[i];
    	}
    }
    return match;
}

uint16_t checksum_RFC1624(struct iphdr *ip_hdr, size_t length) {
	/* formula: HC' = ~(~HC + ~m + m')
	 * HC  - old checksum in header
	 * HC'- new checksum in header
	 * m - old value of a 16-bit field
     * m' - new value of a 16-bit field
	 */

	uint16_t oldttl = (uint16_t)(ip_hdr->ttl + 1);
	uint16_t newchecksum = ntohl((~(ip_hdr->check))&0xffff);
	newchecksum += ntohl((uint16_t)~oldttl);
	newchecksum += ntohl((uint16_t)ip_hdr->ttl);
	while (newchecksum >> 16) {
		newchecksum = (newchecksum & 0xffff) + (newchecksum >> 16);
	}

	return htons(~newchecksum);

}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	m.size = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);	
	init();

	// parsarea tabelei de rutare
	rtable_size = read_rtable("rtable.txt"); 
	
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		ether_header *eth_hdr = (ether_header *)m.payload;
		ether_arp *arp = (ether_arp*)(m.payload + sizeof(struct ether_header));
		iphdr *ip_hdr = (iphdr *)(m.payload + sizeof(struct ether_header));
		icmphdr *icmp_hdr = (icmphdr *)(m.payload + ICMP_OFF);
		
		// pp ca nu s-a adaugat nicio intrare noua in tabela ARP, deci nu voi putea forwarda alte pachete din coada
		int update_arp_table = 0; 
		
		// pp ca pachetul nu a fost destinat routerului
		bool to_router = false;
		int matchy_interface = -1;
		
		for (int i = 0; i < 4; i++) {
			if (ip_hdr->daddr == inet_addr(get_interface_ip(i))) {
				to_router = true;
			}

			if (htonl(to_u32(arp->arp_tpa)) == htonl(inet_addr(get_interface_ip(i)))) {
				matchy_interface = i;
			}
		}

		/****** ARP REQUEST destinat routerului => generez ARP REPLY ******/

		// daca pachetul e destinat routerului si e de tip ARP REQUEST, generez un ARP REPLY
		if(matchy_interface != -1 && htons(arp->arp_op) == ARPOP_REQUEST) {			
			// actualizez mac-ul sender-ului si al target-ului
			swap_mac(arp->arp_sha, arp->arp_tha); 
			get_interface_mac(matchy_interface, arp->arp_sha);

			// actualizez ip-ul sender-ului si al target-ului
			arp->arp_op = htons(ARPOP_REPLY);
			swap_arp_ip(arp->arp_spa, arp->arp_tpa);

			// completez headerul de ethernet cu mac-urile corespunzatoare
			memcpy(eth_hdr->ether_shost, arp->arp_sha, sizeof(arp->arp_sha));
			memcpy(eth_hdr->ether_dhost, arp->arp_tha, sizeof(arp->arp_tha));

			// trimit arp reply-ul catre sursa
			send_packet(matchy_interface, &m);

			continue;
		}

		/****** ARP REPLY => updatez tabela ARP *******/

		if (htons(arp->arp_op) == ARPOP_REPLY) {
			struct arp_entry entry;

			entry.ip = to_u32(arp->arp_spa);
			memcpy(entry.mac, arp->arp_sha, sizeof(arp->arp_sha));
			
			int found = 0;
			for (unsigned i = 0; i < arp_table.size() && !found; i++) {
				if (arp_table[i].ip == entry.ip) {
					found = 1;
				}
			}

			if (found == 0) {			
				arp_table.push_back(entry);
				update_arp_table = 1; // acum voi putea forwarda si alte mesaje din coada
			}

		}


		/**** pachetul a fost de tip ARP REPLY si am adaugat o intrare noua in TABELA ARP => dirijez pachetele din COADA ****/

		if (htons(eth_hdr->ether_type) == ETHERTYPE_ARP && htons(arp->arp_op) == ARPOP_REPLY && update_arp_table == 1) {
			int packets_to_verify = packet_queue.size();
			packet p;

			while (packets_to_verify != 0) {
				p = packet_queue.front();
				packet_queue.pop();

				struct ether_header *ethhdr = (struct ether_header *)p.payload;
				struct iphdr *iphdr = (struct iphdr *)(p.payload + IP_OFF);
				
				struct route_table_entry *best_route = get_best_route(iphdr->daddr);
				struct arp_entry *best_ARP_entry = get_arp_entry(best_route->next_hop);
				

				if (best_ARP_entry == NULL) {
					packet_queue.push(p);
				} else {
					memcpy(ethhdr->ether_dhost, best_ARP_entry->mac, sizeof(best_ARP_entry->mac));
					iphdr->check = 0;
					iphdr->check = checksum(iphdr, sizeof(struct iphdr));
					send_packet(best_route->interface, &p);
				}

				packets_to_verify--;
			}

			continue;
		}


		if (to_router == true) {
			if (icmp_hdr->type == ICMP_ECHO) {
			    m.size = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);	

				// setez campul time to leave pentru pachetul care va semnala sursei ca a trimit un raspuns
				ip_hdr->ttl = 64;	

				// interschimb ip-ul sursa cu ip-ul destinatie	
				swap_ip(ip_hdr->saddr, ip_hdr->daddr);
				
				// ruta pe care pachetul va merge inapoi spre cel care l-a trimis
				struct route_table_entry *route_back_to_source = get_best_route(ip_hdr->daddr);

				// updatez TTL-ul
				ip_hdr->ttl = ip_hdr->ttl - 1;

				// recalculez suma de control pentru headerul ip
				ip_hdr->check = 0;
				ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr)); 
				
				// interschimb mac-ul sursa cu mac-ul destinatie
				swap_mac(eth_hdr->ether_shost, eth_hdr->ether_dhost);
				
				// actualizez tipul headerul icmp la ICMP_ECHOREPLY
				icmp_hdr->type = ICMP_ECHOREPLY;
				icmp_hdr->code = 0;

				// recalculez suma de control pentru headerul icmp
				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = checksum(icmp_hdr, sizeof(struct iphdr));
				
				// trimit spre sursa pachetul de tip ICMP REPLY
				send_packet(route_back_to_source->interface, &m);
			
				continue;				
			}
		}

		/* verific checksum-ul */
		__u16 old_check = ip_hdr->check;
		ip_hdr->check = 0;
		if (checksum(ip_hdr, sizeof(struct iphdr)) != old_check) {
			continue;
		}
		/* verific TTL > 1 => pachetul e ok; TTL <= 1 => Time Exceeded */
		if (ip_hdr->ttl == 1 || ip_hdr->ttl == 0) {
			m.size = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);	

			ip_hdr->version = 4;
			ip_hdr->ihl = 5;
			ip_hdr->tos = 0;
			ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
			ip_hdr->protocol = IPPROTO_ICMP;
			ip_hdr->frag_off = 0;
			ip_hdr->ttl = 64;
			
			// interschimb ip-ul sursa cu ip-ul destinatie
			swap_ip(ip_hdr->saddr, ip_hdr->daddr);

			// interschimb mac-ul sursa cu mac-ul destinatie
			swap_mac(eth_hdr->ether_shost, eth_hdr->ether_dhost);

			struct route_table_entry *route_back_to_source = get_best_route(ip_hdr->daddr);
			
			// recalculez suma de control pentru headerul ip
			ip_hdr->check = 0;
			ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr)); 
			
			// actualizez tipul headerul icmp la time exceeded
			icmp_hdr->type = ICMP_TIME_EXCEEDED;
			icmp_hdr->code = 0;

			// recalculez suma de control pentru headerul icmp
			icmp_hdr->checksum = 0;
			icmp_hdr->checksum = checksum(icmp_hdr, sizeof(struct iphdr));
		
			// trimit inapoi spre sursa pachetul, semnalandu-i time excedeed
			send_packet(route_back_to_source->interface, &m);

			continue;
		}


		/* caut cea mai potrivita ruta; daca ea nu exista in tabela de rutare => destination unreachable*/
		struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
		if (best_route == NULL) { 
			m.size = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
			
			// setez campul time to leave pentru pachetul care va semnala sursei destination unreachable
			ip_hdr->version = 4;
			ip_hdr->ihl = 5;
			ip_hdr->tos = 0;
			ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
			ip_hdr->ttl = 64;
			ip_hdr->protocol = IPPROTO_ICMP;
			ip_hdr->frag_off = 0;

			// interschimb ip-ul sursa cu ip-ul destinatie	
			swap_ip(ip_hdr->saddr, ip_hdr->daddr);
			
			// interschimb mac-ul sursa cu mac-ul destinatie
			swap_mac(eth_hdr->ether_shost, eth_hdr->ether_dhost);

			// ruta pe care pachetul va merge inapoi spre cel care l-a trimis
			struct route_table_entry *route_back_to_source = get_best_route(ip_hdr->daddr);

			// recalculez suma de control pentru headerul ip
			ip_hdr->check = 0;
			ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr)); 
			
			// actualizez tipul headerul icmp la destination unreachable
			icmp_hdr->type = ICMP_DEST_UNREACH; 
			icmp_hdr->code = 0;

			// recalculez suma de control pentru headerul icmp
			icmp_hdr->checksum = 0;
			icmp_hdr->checksum = checksum(icmp_hdr, sizeof(struct iphdr));

			// trimit inapoi spre sursa pachetul, semnalandu-i ca destinatia nu e valida
			send_packet(route_back_to_source->interface, &m);

			continue;
		}

		/* fac update la TTL si recalculez checksum-ul */
		ip_hdr->ttl = ip_hdr->ttl - 1;

		ip_hdr->check = 0;
		ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr)); // suma se calc doar pe header

		/****** ARP REQUEST ********/

		/* caut intrarea corespunzatoare in tabela ARP si updatez adresa Ethernet */

		struct arp_entry *best_ARP_entry = get_arp_entry(best_route->next_hop);
		if (best_ARP_entry == NULL) {
			// salvez pachetul in coada pentru retransmitere
			get_interface_mac(best_route->interface, eth_hdr->ether_shost); // setez doar mac-ul sursa
			packet_queue.push(m);
			
			// generez un nou pachet pt a transmite un ARP REQUEST 
			packet req;

			struct ether_header *eth_hdr_req = (struct ether_header *)req.payload;
			struct ether_arp *arp_hdr_req = (struct ether_arp*)(req.payload + IP_OFF);
			req.size = sizeof(struct ether_header) + sizeof(struct ether_arp);

			// generez un ARP REQUEST
			eth_hdr_req->ether_type = htons(ETHERTYPE_ARP);
			arp_hdr_req->arp_hrd = htons(ARPHRD_ETHER);
			arp_hdr_req->arp_pro = htons(ETHERTYPE_IP); // ipv4 = 0x0800
			arp_hdr_req->arp_hln = 6; 
			arp_hdr_req->arp_pln = 4;
			arp_hdr_req->arp_op = htons(ARPOP_REQUEST);
							
			// actualizez mac-ul sender-ului si al target-ului
			memcpy(arp_hdr_req->arp_sha, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
			memset(arp_hdr_req->arp_tha, 0, sizeof(BROADCAST));

			// actualizez ip-ul sender-ului si al target-ului
			*(uint32_t *) arp_hdr_req->arp_spa = inet_addr(get_interface_ip(best_route->interface));
			*(uint32_t *) arp_hdr_req->arp_tpa = ip_hdr->daddr;

			// completez headerul de ethernet cu mac-urile corespunzatoare
			memcpy(eth_hdr_req->ether_shost, arp->arp_sha, sizeof(arp->arp_sha));
			memcpy(eth_hdr_req->ether_dhost, BROADCAST, sizeof(BROADCAST));


			send_packet(best_route->interface, &req);

			continue;
		}


		// MAC sursa
		get_interface_mac(best_route->interface, eth_hdr->ether_shost);
			
		// MAC destinatie
		memcpy(eth_hdr->ether_dhost, best_ARP_entry->mac, sizeof(best_ARP_entry->mac));

		// forwardez pachetul catre best_route->interface
		send_packet(best_route->interface, &m);

	}
}