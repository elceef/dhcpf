/*
  dhcpf
  (c) Marcin Ulikowski <elceef@itsec.pl>


  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <pcap.h>
#include <signal.h>
#include <pwd.h>

#include "dhcp.h"
#include "udpip.h"
#include "fp.h"

#define VERSION "0.7c"

struct fprint fp[FP_MAX_PRINTS];
unsigned short fpcnt = 0;

unsigned int udpc = 0;
unsigned short fhlen = 0; // frame header length


char* opt2bin(char *opt)
{
  
  char *pch;
  int pcnt = 0;
  pch = strtok(opt, ",");

  while (pch != NULL)
  {

    opt[pcnt++] = atoi(pch);
    pch = strtok(NULL, ",");

  }

  opt[pcnt++] = 0;

  return opt;

}


char* bin2opt(unsigned char *bin)
{

  static char opt[255];
  char *o;
  unsigned char i;

  bzero(opt, sizeof(opt));

  for (i = 0; i < strlen(bin); i++)
  {

    o = strdup(opt);
    snprintf(opt, sizeof(opt), "%s%s%u", o, (i>0)?",":"", *(bin+i));
    free(o);

  }

  return opt;

}


char* bin2mac(unsigned char *chaddr, unsigned char hlen)
{

  static char mac[255];
  char *o;
  unsigned char i;

  bzero(mac, sizeof(mac));

  for (i = 0; i < hlen; i++)
  {

    o = strdup(mac);
    snprintf(mac, sizeof(mac), "%s%s%02x", o, (i>0)?":":"", chaddr[i]);
    free(o);

  }

  return mac;

}


unsigned char round_ttl(unsigned char ttl)
{

  if (ttl <= 32) return 32;
  else
  if (ttl <= 64 && ttl > 32) return 64;
  else
  if (ttl <= 128 && ttl > 64) return 128;
  else
  if (ttl > 128) return 255;

}


// super fast strcmp() for fixed length string

char* strcmp6(char *heystack, char *needle)
{

  int heys = heystack[0] << 24 | heystack[1] << 16 | heystack[2] << 8 | heystack[3];
  short tack = heystack[4] << 8 | heystack[5];
  int nee = needle[0] << 24 | needle[1] << 16 | needle[2] << 8 | needle[3];
  short dle = needle[4] << 8 | needle[5];

  if ( heys == nee && tack == dle )
    return heystack;

  return 0;

}


char* find_ether_oui(unsigned char *mac)
{

  FILE *o;
  static unsigned char oui[9];
  unsigned char buf[32];
  unsigned char eth[7];

  if (o = fopen("oui", "r"))
  {

    snprintf(eth, sizeof(eth), "%02X%02X%02X", *mac, *(mac+1), *(mac+2));

    bzero(oui, sizeof(oui));

    while (!feof(o))
    {

      fgets(buf, sizeof(buf), o);

      if (strcmp6(buf, eth))
      {

        memcpy(oui, buf+7, sizeof(oui)-1);
        fclose(o);

        return (char*)oui;

      }

    }

    fclose(o);

  }

  return (char*)"UnknownOUI";

}


//TODO:
int load_dhcp_prints(void)
{

  FILE *fpd;
  char line[FP_LINE_LEN];
  char osname[FP_OSNAME_LEN];
  char vendor[FP_VENDOR_LEN];
  char opts[FP_OPTS_LEN];
  char opt55[FP_OPT55_LEN];
  int ttl, i = 0;

  if (!(fpd = fopen(FP_DATABASE, "r")))
    fprintf(stderr, "Error: Unable to open %s - %s\n", FP_DATABASE, strerror(errno));

  while (i++ < FP_MAX_PRINTS)
  {

    fgets(line, FP_LINE_LEN, fpd);

    if (feof(fpd))
      break;

    if (line[0] == '#' || line[0] == '\n' || line[0] == '!')
      continue;

    line[strlen(line)-1] = 0;

    if (sscanf(line, "%d|%[0-9,*]|%[0-9,*]|%[^|]|%[^|]", &ttl, opts, opt55, vendor, osname) != 5)
      fprintf(stderr, "Error: Syntax mismatch on line %u in %s\n", i, FP_DATABASE);

    if (!strcmp(vendor, "(null)"))
      bzero(vendor, sizeof(vendor));

    fp[fpcnt].ttl = ttl;
    fp[fpcnt].opts = (!strcmp(opts, "*")) ? strdup(opts) : strdup(opt2bin(opts));
    fp[fpcnt].opt55 = (!strcmp(opt55, "*")) ? strdup(opt55) : strdup(opt2bin(opt55));
    fp[fpcnt].vendor = strdup(vendor);
    fp[fpcnt].osname = strdup(osname);
    
    fpcnt++;

  }

  fclose(fpd);

  return fpcnt;

}


char* osfp(unsigned char ttl, unsigned char *opts, unsigned char *opt55, unsigned char *vendor)
{

  unsigned short i;

  for (i = 0; i < fpcnt; i++)
  {

    if (!strcmp(fp[i].opt55, opt55) || !strcmp(fp[i].opt55, "*"))
      if (!strcmp(fp[i].opts, opts) || !strcmp(fp[i].opts, "*")) 
        if (!strcmp(fp[i].vendor, vendor))
          if (fp[i].ttl == ttl || !fp[i].ttl)
            return fp[i].osname;

  }

  static char rawsig[255];
  char *o, *o55;

  o = strdup(bin2opt(opts));
  o55 = strdup(bin2opt(opt55));
  snprintf(rawsig, sizeof(rawsig), "%u|%s|%s|%s|Unknown", ttl, o, o55, (strlen(vendor))?vendor:"(null)");
  free(o);
  free(o55);

  return rawsig;

}


char* long2ip(unsigned int ip)
{

  unsigned char *ia;
  static char dotip[16];
  ia = (unsigned char *)&ip;
  snprintf(dotip, sizeof(dotip), "%u.%u.%u.%u", ia[0], ia[1], ia[2], ia[3]);

  return (char*)dotip;

}


void catch_signal()
{

  printf("\nSignal received. Shutdown.\nProcessed %u DHCP requests.\n\nQuestions? Complaints? You can reach the author at <marcin@ulikowski.pl>\n", udpc);
  exit(0);

}


void set_fhlen(unsigned int dlink_type)
{

  switch (dlink_type)
  {

    case DLT_RAW:
      fhlen = 0; break;

    case DLT_SLIP:
      fhlen = 16; break;

    case DLT_EN10MB:
      fhlen = 14; break;

    case DLT_NULL:
    case DLT_PPP:
      fhlen = 4; break;

    case DLT_LOOP:
#ifdef DLT_PPP_SERIAL
    case DLT_PPP_SERIAL:
#endif
#ifdef DLT_PPP_ETHER
    case DLT_PPP_ETHER:
#endif
      fhlen = 8; break;

#ifdef DLT_PFLOG
    case DLT_PFLOG:
      fhlen = 28; break;
#endif

#ifdef DLT_LINUX_SLL
    case DLT_LINUX_SLL:
      fhlen = 16; break;
#endif

    default:
      fprintf(stderr, "Warning: unable to find device link type!\n");
      break;

  }

}


void process_datagram(unsigned char *args, struct pcap_pkthdr *header, unsigned char *datagram)
{

  unsigned char options[255], option55[255], vendor[255], hostname[255], opt82_remote_id[255];
  unsigned char dhcptype;
  unsigned int reqip = 0, optc = 0;
  unsigned short vlanid = 0, opt82_circuit_vlan = 0;
  unsigned short ethtype;
  unsigned int i, j, k;
  unsigned char *p, *p82;
  unsigned char opt, len, opt82, len82;
  unsigned char opt82_circuit_unit = 0, opt82_circuit_port = 0;

  unsigned char *ethp = (datagram + 12);
  memcpy(&ethtype, ethp, 2);
#if BYTE_ORDER == LITTLE_ENDIAN
  ethtype = ntohs(ethtype);
#endif

  if (ethtype == 0x8100)
  {

    fhlen += 4; // 802.1Q VLAN
    ethp += 2;
    memcpy(&vlanid, ethp, 2);
    vlanid &= 0xFF0F; // remove PCP & CFI
#if BYTE_ORDER == LITTLE_ENDIAN
    vlanid = ntohs(vlanid);
#endif

  }

  struct iphdr *ip = (struct iphdr *)(datagram + fhlen);
  struct udphdr *udp = (struct udphdr *)(datagram + sizeof(struct iphdr) + fhlen);
  struct dhcpmsg *dhcp = (struct dhcpmsg *)(datagram + sizeof(struct iphdr) + sizeof(struct udphdr) + fhlen);

  if (ethtype == 0x8100) // 802.1Q VLAN
    fhlen -= 4;

#if BYTE_ORDER == LITTLE_ENDIAN
  udp->len = htons(udp->len);
#endif

  p = (unsigned char *)(dhcp->options);

  bzero(hostname, sizeof(hostname));
  bzero(option55, sizeof(option55));
  bzero(options, sizeof(options));
  bzero(vendor, sizeof(vendor));
  bzero(opt82_remote_id, sizeof(opt82_remote_id));

  for (i = 0; i < (udp->len - sizeof(struct udphdr) - sizeof(struct dhcpmsg)); i++)
  {

    memcpy(&opt, p, 1);
    memcpy(&len, p+1, 1);
    p+=2;

    // omit pad, end and option82!
    if (opt != DHCP_OPTION_PAD && opt != DHCP_OPTION_END && opt != DHCP_OPTION_DHCP_AGENT_OPTIONS)
      options[optc++] = opt;

    switch (opt)
    {

      case DHCP_OPTION_DHCP_MESSAGE_TYPE:
        dhcptype = *p;
        break;

      case DHCP_OPTION_DHCP_REQUESTED_ADDRESS:
        memcpy(&reqip, p, sizeof(reqip));
        break;

      case DHCP_OPTION_DHCP_PARAMETER_REQUEST_LIST: // 55
        for (j = 0; j < len; j++)
          option55[j] = *(p+j);
        break;

      case DHCP_OPTION_VENDOR_CLASS_IDENTIFIER:
        memcpy(&vendor, p, len);
        break;

      case DHCP_OPTION_HOST_NAME:
        memcpy(hostname, p, len);
        break;

      case DHCP_OPTION_DHCP_AGENT_OPTIONS: // 82
        p82 = p;

        for (j = 0; j < len; j++)
        {

          memcpy(&opt82, p82, 1);
          memcpy(&len82, p82+1, 1);
          p82+=2;

          switch (opt82)
          {

            case DHCP_OPTION82_REMOTE_ID:
              memcpy(opt82_remote_id, p82+2, len82-2);
              break;

            case DHCP_OPTION82_CIRCUIT_ID:
              // make sure we are not dealing with some custom string
              if (*p82 == 0 && *(p82+1) == 4)
              {

                memcpy(&opt82_circuit_vlan, p82+2, 2);
#if BYTE_ORDER == LITTLE_ENDIAN
                opt82_circuit_vlan = htons(opt82_circuit_vlan);
#endif
                memcpy(&opt82_circuit_unit, p82+4, 1);
                memcpy(&opt82_circuit_port, p82+5, 1);

              }
              break;

            default:
#ifdef _DEBUG
              printf("subopt82=%u len=%u val=", opt82, len82);

              for (k = 0; k < len82; k++)
                printf("%02x", *(p82+k));

              putchar('|');

              for (k = 0; k < len82; k++)
              {

                if (*(p82+k) >= 32 && *(p82+k) < 128)
                  putchar(*(p82+k));
                else
                  putchar('.');

              }

              putchar(' ');
#endif
              break;
          }

          p82 += len82;
          j += len82 + 1;

        }
        break;

      case DHCP_OPTION_PAD:
      case DHCP_OPTION_END:
        break;

      default:
#ifdef _DEBUG
        printf("opt=%u len=%u val=", opt, len);

        for (j = 0; j < len; j++)
          printf("%02x", *(p+j));

        putchar('|');

        for (j = 0; j < len; j++)
        {

          if (*(p+j) >= 32 && *(p+j) < 128)
            putchar(*(p+j));
          else
            putchar('.');

        }

        putchar(' ');
#endif
        break;

    }

    p += len;
    i += len + 1;

  } // options

  switch (dhcptype)
  {

    case DHCP_DISCOVER: printf("Discover"); break;
    case DHCP_REQUEST:  printf("Request"); break;
    case DHCP_INFORM:   printf("Inform"); break;
    default: return; break;

  }

  printf(" from %s_%s (%s)", find_ether_oui(dhcp->chaddr), bin2mac(dhcp->chaddr, dhcp->hlen)+9, bin2mac(dhcp->chaddr, dhcp->hlen));

  if (vlanid)
    printf(" @ VLAN %u\n", vlanid);
  else
    putchar('\n');

  printf("  system\t= %s\n", osfp(round_ttl(ip->ttl), options, option55, vendor));

  if (strlen(hostname))
    printf("  hostname\t= %s\n", hostname);
  if (reqip)
    printf("  req ipaddr\t= %s\n", long2ip(reqip));
  if (strlen(opt82_remote_id))
    printf("  option82\t= remote_id %s circuit_id vlan %u unit %u port %u\n", bin2mac(opt82_remote_id, 6), opt82_circuit_vlan, opt82_circuit_unit, opt82_circuit_port);

  putchar('\n');

  fflush(stdout);

  udpc++;

}


int main(int argc, char *argv[])
{

  char errbuff[PCAP_ERRBUF_SIZE];
  struct bpf_program filter;
  pcap_t *pt;
  struct passwd *nobody;

  signal(SIGHUP, &catch_signal);
  signal(SIGINT, &catch_signal);
  signal(SIGTERM, &catch_signal);

  printf("=== dhcpf " VERSION ": passive DHCP fingerprinting ===\n\n");

  if (argc != 2)
  {

    fprintf(stderr, "Error: Missing argument. Interface not specified\n");
    exit(1);

  }

  if (geteuid())
  {

    fprintf(stderr, "Error: You need to have root privileges\n");
    exit(1);

  }

  printf("Successfully loaded %d DHCP-prints.\n\n", load_dhcp_prints());

  if (!(pt = pcap_open_live(argv[1], 1500, 1, 1, errbuff)))
    fprintf(stderr, "Error: Unable to open device %s\n", argv[1]);

  // drop priv
  nobody = getpwnam("nobody");

  if (nobody && nobody->pw_uid)
    setuid(nobody->pw_uid);
  else
    fprintf(stderr, "Warning: Unable to drop privileges!\n");

  set_fhlen(pcap_datalink(pt));

  pcap_compile(pt, &filter, "udp[9] == 1 and src port 68 and dst port 67 and greater 267", 1, 0);

  pcap_setfilter(pt, &filter);
  
  pcap_loop(pt, -1, (pcap_handler)&process_datagram, 0);

  pcap_close(pt);
 
  return 0;

}
