struct iphdr {
  unsigned char  ihl:4,     /* header len */
                 version:4;
  unsigned char  tos;       /* type of service */
  unsigned short len,       /* total length */
                 id,        /* identification */
                 frag_off;  /* fragment offset + DF/MF */
  unsigned char  ttl,       /* time to live */
                 protocol;  /* protocol */
  unsigned short cksum;     /* checksum */
  unsigned int   saddr,     /* source */
                 daddr;     /* destination */
};


struct udphdr {
  unsigned short sport,  /* source port */
                 dport,  /* destination port */
                 len,    /* length of entire datagram (header+data) */
                 cksum;  /* checksum */
};

