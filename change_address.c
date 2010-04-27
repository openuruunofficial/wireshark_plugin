/*
 * change_address.c
 * Simple program to modify a packet trace to change out IP addresses (and
 * ports for good measure) in TCP traffic. Make sure there is *only* TCP
 * traffic in the trace, and that the program is run once for each connection.
 *
 * Copyright (C) 2008-2009  a'moaca'
 *
 * $Id: $
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD /* for Linux */
#endif
#include <netinet/tcp.h>
#include <pcap.h>

#define BUFSIZE 1600

int main(int argc, char *argv[]) {
  int len, ret, off;
  in_addr_t from, to;
  int from_port, to_port;

  char errbuf[PCAP_ERRBUF_SIZE];
  unsigned char packetbuf[BUFSIZE];
  const unsigned char *data;
  pcap_t *inp;
  pcap_dumper_t *outp;
  struct pcap_pkthdr hdr;
  struct ip *iph;
  struct tcphdr *tcph;

  if (argc != 7) {
    fprintf(stderr, "Usage: %s <input file> <ip address> <port> <output file> <new address> <new port>\n\t(works only on TCP traffic, and does not recompute TCP checksums)\n",
	    argv[0]);
    exit(1);
  }

  from = inet_addr(argv[2]);
  if (from == INADDR_NONE) {
    fprintf(stderr, "Invalid IP address: %s\n", argv[2]);
    exit(1);
  }
  to = inet_addr(argv[5]);
  if (to == INADDR_NONE) {
    fprintf(stderr, "Invalid IP address: %s\n", argv[5]);
    exit(1);
  }
  if (sscanf(argv[3], "%u", &from_port) != 1) {
    fprintf(stderr, "Invalid port: %s\n", argv[3]);
    exit(1);
  }
  if (sscanf(argv[6], "%u", &to_port) != 1) {
    fprintf(stderr, "Invalid port: %s\n", argv[6]);
    exit(1);
  }
  from_port = htons(from_port);
  to_port = htons(to_port);

  inp = pcap_open_offline(argv[1], errbuf);
  if (!inp) {
    fprintf(stderr, "%s: Cannot open file %s: %s\n", argv[0], argv[1],
	    errbuf);
    exit(1);
  }
  outp = pcap_dump_open(inp, argv[4]);
  if (!outp) {
    fprintf(stderr, "%s: Cannot open file %s: %s\n", argv[0], argv[4],
	    pcap_geterr(inp));
    pcap_close(inp);
    exit(1);
  }

  data = pcap_next(inp, &hdr);
  while (data) {
    len = hdr.caplen;
    if (len < 14) {
      pcap_dump((unsigned char *)outp, &hdr, data);
      data = pcap_next(inp, &hdr);
      continue;
    }
    /* check for non-IP (arp is what got me) */
    off = *(short*)(data+12);
    if (ntohs(off) != 0x0800) {
      /* not an IP packet */
      pcap_dump((unsigned char *)outp, &hdr, data);
      data = pcap_next(inp, &hdr);
      continue;
    }
    /* skip headers */
    off = 14;
    len -= 14;
    if (len < 20) {
      /* bail */
      fprintf(stderr, "truncated packet\n");
      break;
    }
    iph = (struct ip *)(data+off);
    if (len+off < ntohs(iph->ip_len)) {
      fprintf(stderr, "truncated packet\n");
      break;
    }
    len = ntohs(iph->ip_len);
    /* check for non-TCP */
    if (iph->ip_p != IPPROTO_TCP) {
      pcap_dump((unsigned char *)outp, &hdr, data);
      data = pcap_next(inp, &hdr);
      continue;
    }
    off += iph->ip_hl*4;
    len -= iph->ip_hl*4;
    if (len < 20) {
      /* bail */
      fprintf(stderr, "truncated packet\n");
      break;
    }
    tcph = (struct tcphdr *)(data+off);
    off += tcph->th_off*4;
    len -= tcph->th_off*4;

    if (iph->ip_src.s_addr == from && tcph->th_sport == from_port) {
      iph->ip_src.s_addr = to;
      tcph->th_sport = to_port;
    }
    if (iph->ip_dst.s_addr == from && tcph->th_dport == from_port) {
      iph->ip_dst.s_addr = to;
      tcph->th_dport = to_port;
    }

    pcap_dump((unsigned char *)outp, &hdr, data);

    data = pcap_next(inp, &hdr);
  }
  pcap_close(inp);
  pcap_dump_close(outp);
  exit(0);
}
