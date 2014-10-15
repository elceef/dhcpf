// BOOTP (RFC951) message types
#define DHCP_BOOTREQUEST  1
#define DHCP_BOOTREPLY    2

// DHCP message types
#define DHCP_DISCOVER     1
#define DHCP_OFFER        2
#define DHCP_REQUEST      3
#define DHCP_DECLINE      4
#define DHCP_ACK          5
#define DHCP_NAK          6
#define DHCP_RELEASE      7
#define DHCP_INFORM       8

// DHCP options
#define DHCP_OPTION_PAD                         0
#define DHCP_OPTION_SUBNET_MASK                 1
#define DHCP_OPTION_TIME_OFFSET                 2
#define DHCP_OPTION_ROUTERS                     3
#define DHCP_OPTION_TIME_SERVERS                4
#define DHCP_OPTION_NAME_SERVERS                5
#define DHCP_OPTION_DOMAIN_NAME_SERVERS         6
#define DHCP_OPTION_LOG_SERVERS                 7
#define DHCP_OPTION_COOKIE_SERVERS              8
#define DHCP_OPTION_LPR_SERVERS                 9
#define DHCP_OPTION_IMPRESS_SERVERS             10
#define DHCP_OPTION_RESOURCE_LOCATION_SERVERS   11
#define DHCP_OPTION_HOST_NAME                   12
#define DHCP_OPTION_BOOT_SIZE                   13
#define DHCP_OPTION_MERIT_DUMP                  14
#define DHCP_OPTION_DOMAIN_NAME                 15
#define DHCP_OPTION_SWAP_SERVER                 16
#define DHCP_OPTION_ROOT_PATH                   17
#define DHCP_OPTION_EXTENSIONS_PATH             18
#define DHCP_OPTION_IP_FORWARDING               19
#define DHCP_OPTION_NON_LOCAL_SOURCE_ROUTING    20
#define DHCP_OPTION_POLICY_FILTER               21
#define DHCP_OPTION_MAX_DGRAM_REASSEMBLY        22
#define DHCP_OPTION_DEFAULT_IP_TTL              23
#define DHCP_OPTION_PATH_MTU_AGING_TIMEOUT      24
#define DHCP_OPTION_PATH_MTU_PLATEAU_TABLE      25
#define DHCP_OPTION_INTERFACE_MTU               26
#define DHCP_OPTION_ALL_SUBNETS_LOCAL           27
#define DHCP_OPTION_BROADCAST_ADDRESS           28
#define DHCP_OPTION_PERFORM_MASK_DISCOVERY      29
#define DHCP_OPTION_MASK_SUPPLIER               30
#define DHCP_OPTION_ROUTER_DISCOVERY            31
#define DHCP_OPTION_ROUTER_SOLICITATION_ADDRESS 32
#define DHCP_OPTION_STATIC_ROUTES               33
#define DHCP_OPTION_TRAILER_ENCAPSULATION       34
#define DHCP_OPTION_ARP_CACHE_TIMEOUT           35
#define DHCP_OPTION_IEEE802_3_ENCAPSULATION     36
#define DHCP_OPTION_DEFAULT_TCP_TTL             37
#define DHCP_OPTION_TCP_KEEPALIVE_INTERVAL      38
#define DHCP_OPTION_TCP_KEEPALIVE_GARBAGE       39
#define DHCP_OPTION_NIS_DOMAIN                  40
#define DHCP_OPTION_NIS_SERVERS                 41
#define DHCP_OPTION_NTP_SERVERS                 42
#define DHCP_OPTION_VENDOR_ENCAPSULATED_OPTIONS 43
#define DHCP_OPTION_NETBIOS_NAME_SERVERS        44
#define DHCP_OPTION_NETBIOS_DD_SERVER           45
#define DHCP_OPTION_NETBIOS_NODE_TYPE           46
#define DHCP_OPTION_NETBIOS_SCOPE               47
#define DHCP_OPTION_FONT_SERVERS                48
#define DHCP_OPTION_X_DISPLAY_MANAGER           49
#define DHCP_OPTION_DHCP_REQUESTED_ADDRESS      50
#define DHCP_OPTION_DHCP_LEASE_TIME             51
#define DHCP_OPTION_DHCP_OPTION_OVERLOAD        52
#define DHCP_OPTION_DHCP_MESSAGE_TYPE           53
#define DHCP_OPTION_DHCP_SERVER_IDENTIFIER      54
#define DHCP_OPTION_DHCP_PARAMETER_REQUEST_LIST 55
#define DHCP_OPTION_DHCP_MESSAGE                56
#define DHCP_OPTION_DHCP_MAX_MESSAGE_SIZE       57
#define DHCP_OPTION_DHCP_RENEWAL_TIME           58
#define DHCP_OPTION_DHCP_REBINDING_TIME         59
#define DHCP_OPTION_VENDOR_CLASS_IDENTIFIER     60
#define DHCP_OPTION_DHCP_CLIENT_IDENTIFIER      61
#define DHCP_OPTION_NWIP_DOMAIN_NAME            62
#define DHCP_OPTION_NWIP_SUBOPTIONS             63
#define DHCP_OPTION_USER_CLASS                  77
#define DHCP_OPTION_FQDN                        81
#define DHCP_OPTION_DHCP_AGENT_OPTIONS          82
#define DHCP_OPTION_END                         255

#define DHCP_OPTION82_CIRCUIT_ID                1
#define DHCP_OPTION82_REMOTE_ID                 2


// PORTS
#define DHCP_CLIENT_PORT        68      
#define DHCP_SERVER_PORT        67

// LENGTHS
#define DHCP_CHADDR_LEN         16
#define DHCP_SNAME_LEN          64
#define DHCP_FILE_LEN           128
#define DHCP_OPTIONS_LEN        512
#define DHCP_MIN_OPTIONS_LEN    68

struct __attribute__((packed)) dhcpmsg {
  unsigned char  op;                       // Message opcode/type
  unsigned char  htype;                    // Hardware addr type
  unsigned char  hlen;                     // Hardware addr length
  unsigned char  hops;                     // Number of relay agent hops from client
  unsigned int   xid;                      // Transaction ID
  unsigned short secs;                     // Seconds since client started looking
  unsigned short flags;                    // Flag bits
  unsigned int   ciaddr;                   // Client IP address (if already in use)
  unsigned int   yiaddr;                   // Client IP address
  unsigned int   siaddr;                   // IP address of next server to talk to
  unsigned int   giaddr;                   // DHCP relay agent IP address
  unsigned char  chaddr[DHCP_CHADDR_LEN];  // Client hardware address
  char           sname[DHCP_SNAME_LEN];    // Server name
  char           file[DHCP_FILE_LEN];      // Boot filename
  unsigned int   cookie;                   // DHCP option cookie
  unsigned char  options[0];               // Optional parameters (actual length dependent on MTU).
};
