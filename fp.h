#define FP_MAX_PRINTS 2000
#define FP_LINE_LEN   1020
#define FP_OPTS_LEN   255
#define FP_OPT55_LEN  255
#define FP_VENDOR_LEN 255
#define FP_OSNAME_LEN 255
#define FP_DATABASE   "dhcpf.prints"

struct fprint {
  unsigned char ttl;
  char *opts,
       *opt55,
       *vendor,
       *osname;
};
