#!/bin/bash

sayf() {
  TEXT="$@"
  printf "$TEXT "
  awk "BEGIN { for (j=length(\"$TEXT\"); j<60; j++) printf \".\" }"
  printf " "
}

PROGNAME="dhcpf"
TMP=".dhcpf-tmp"

if [ "$1" = "clean" ]; then
  rm -f "$PROGNAME"
  exit 0
fi

sayf "Checking directory permissions"
touch "$TMP" 2>/dev/null
if [ -f "$TMP" ]; then
  echo "OK"
else
  echo "FAIL (can't create)"
  echo
  echo "Please fix directory permissions and try again."
  echo
  exit 1
fi

REQFILES="dhcpf.c dhcp.h udpip.h fp.h dhcpf.prints oui"
for i in $REQFILES; do
  sayf "Checking file '$i'"
  if [ -s $i ]; then
    echo "Found"
  else
    echo "NOT FOUND!"
    echo
    echo "It seems that the source code or some part of it is missing."
    echo
    exit 1
  fi
done

sayf "Checking for working GCC"
rm -f "$TMP" "$TMP.log" "$TMP.c"
echo "int main() { return 0; }" > "$TMP.c"
gcc "$TMP.c" -o "$TMP" &> "$TMP.log"
if [ -x "$TMP" ]; then
  echo "Works"
else
  echo "FAIL"
  echo
  echo "Your compiler can't produce executables. You need a functioning install"
  echo "of GCC and libc to continue."
  echo
  echo "Verbose output from compilation attempt:"
  cat "$TMP.log"
  echo
  rm -f "$TMP" "$TMP.log" "$TMP.c"
  exit 1
fi

sayf "Checking for working libpcap"
rm -f "$TMP" "$TMP.log" "$TMP.c"
echo -e "#include <pcap.h>\nint main() { char buf[PCAP_ERRBUF_SIZE]; pcap_lookupdev(buf); return 0; }" > "$TMP.c"
gcc "$TMP.c" -o "$TMP" -lpcap &> "$TMP.log"

if [ -x "$TMP" ]; then
  echo "Works"
else
  echo "FAIL"
  echo
  echo "You need a functioning installation of libpcap with development headers."
  echo "You can download it from here:"
  echo 
  echo "http://www.tcpdump.org/#latest-release"
  echo
  echo "Verbose output from an attempt to compile sample code:"
  cat "$TMP.log"
  echo
  rm -f "$TMP" "$TMP.log" "$TMP.c"
  exit 1
fi

echo
sayf "Building $PROGNAME"
rm -f "$PROGNAME" "$TMP" "$TMP.c"
if [ "$1" = "debug" ]; then
  gcc dhcpf.c -o "$PROGNAME" -lpcap -Wall -D_DEBUG &> "$TMP.log"
else
  gcc dhcpf.c -o "$PROGNAME" -lpcap &> "$TMP.log"
fi
if [ -x "$PROGNAME" ]; then
  echo "Done"
else
  echo "FAIL"
  echo
  echo "Well, something went wrong."
  echo "Here is the output from compilation attempt:"
  echo
  cat "$TMP.log"
  echo
  echo "You may want to inform <marcin@ulikowski.pl> about this."
  echo
  exit 1
fi
rm -f "$TMP.log"

echo
echo "That's it! If you encounter any problems or have some suggestions"
echo "please contact the author at <marcin@ulikowski.pl>"
echo
