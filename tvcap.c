#include <stdio.h>
#include <string.h>
#include <err.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <pcap/sll.h>

static void
handle_udp(const u_char *data)
{
	struct udphdr *udp = (void *)data;

	fwrite(data + sizeof(*udp), ntohs(udp->uh_ulen) - sizeof(*udp),
	    1, stdout);
}

static void
handle_ip4(const u_char *data)
{
	struct ip *ip = (void *)data;

	if (ip->ip_p == IPPROTO_UDP)
		handle_udp(data + ip->ip_hl * 4);
}

static void
handle_ip6(const u_char *data)
{
	struct ip6_hdr *ip6 = (void *)data;

	if (ip6->ip6_nxt == IPPROTO_UDP)
		handle_udp(data + sizeof(*ip6));
}

static void
handle_sll(const u_char *data)
{
	struct sll_header *sll = (void *)data;

	switch (ntohs(sll->sll_protocol)) {
	case ETHERTYPE_IP:   handle_ip4(data + sizeof(*sll)); break;
	case ETHERTYPE_IPV6: handle_ip6(data + sizeof(*sll)); break;
	}
}

static void
handle_ethernet(const u_char *data)
{
	struct ether_header *ether = (void *)data;

	switch (ntohs(ether->ether_type)) {
	case ETHERTYPE_IP:   handle_ip4(data + 14); break;
	case ETHERTYPE_IPV6: handle_ip6(data + 14); break;
	}
}

int
main()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap;
	int dlt;
	struct bpf_program filter;
	struct pcap_pkthdr header;
	const u_char *data;

	if (!(pcap = pcap_open_live("any", 4096, 0, 1000, errbuf)))
		errx(1, "%s", errbuf);
	if (pcap_compile(pcap, &filter, "udp port 7252", 0, 0))
		errx(1, "%s", pcap_geterr(pcap));
	if (pcap_setfilter(pcap, &filter))
		errx(1, "%s", pcap_geterr(pcap));

	dlt = pcap_datalink(pcap);

	while ((data = pcap_next(pcap, &header))) {
		if (header.len != header.caplen)
			errx(1, "len != caplen");

		switch (dlt) {
		case DLT_EN10MB:    handle_ethernet(data); break;
		case DLT_LINUX_SLL: handle_sll(data); break;
		case DLT_RAW:       handle_ip4(data); break;
		default:
			errx(1, "unsupported datalinkt type: %d", dlt);
		}
	}

	return 0;
}
