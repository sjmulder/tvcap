#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sysexits.h>
#include <err.h>
#include <sys/types.h>	/* u_char on FreeBSD */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <pcap.h>

#if defined(__NetBSD__)
# include <net/if_ether.h>
#elif defined(__OpenBSD__)
# include <sys/socket.h>
# include <net/if_arp.h>
# include <netinet/if_ether.h>
#elif defined(__sun)
# include <sys/ethernet.h>
#else
# include <net/ethernet.h>
#endif

#if defined(__linux__)
# include <pcap/sll.h>
#endif

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

#ifdef __linux__
static void
handle_sll(const u_char *data)
{
	struct sll_header *sll = (void *)data;

	switch (ntohs(sll->sll_protocol)) {
	case ETHERTYPE_IP:   handle_ip4(data + sizeof(*sll)); break;
	case ETHERTYPE_IPV6: handle_ip6(data + sizeof(*sll)); break;
	}
}
#endif

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
main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter_s[32];
	const char *device = "any";
	pcap_t *pcap;
	int port=7252, dlt, c;
	struct bpf_program filter;
	struct pcap_pkthdr header;
	const u_char *data;

	while ((c = getopt(argc, argv, "p:")) != -1)
		switch (c) {
		case 'p':
			if ((port = atoi(optarg)) < 1)
				errx(1, "bad port");
			break;
		default:
			fputs("usage: tvcap [-p port] [device]\n", stderr);
			return EX_USAGE;
		}

	argc -= optind;
	argv += optind;

	if (argc > 1)
		errx(EX_USAGE, "too many arguments");
	if (argc)
		device = argv[0];

	snprintf(filter_s, sizeof(filter_s), "udp port %d\n", port);

	if (!(pcap = pcap_open_live(device, 4096, 1, 0, errbuf)))
		errx(1, "%s", errbuf);
	if (pcap_compile(pcap, &filter, filter_s, 0, 0))
		errx(1, "%s", pcap_geterr(pcap));
	if (pcap_setfilter(pcap, &filter))
		errx(1, "%s", pcap_geterr(pcap));

	dlt = pcap_datalink(pcap);

	while ((data = pcap_next(pcap, &header))) {
		if (header.len != header.caplen)
			errx(1, "len != caplen");

		switch (dlt) {
		case DLT_EN10MB:    handle_ethernet(data); break;
		case DLT_RAW:       handle_ip4(data); break;
#ifdef __linux__
		case DLT_LINUX_SLL: handle_sll(data); break;
#endif
		default:
			errx(1, "unsupported datalinkt type: %d", dlt);
		}
	}

	return 0;
}
