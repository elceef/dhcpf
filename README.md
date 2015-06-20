dhcpf
=====
It is possible to precisely recognize the operating system on the basis of unique combination
of DHCP options in host requests. This is an example of implementation.

Signatures
----------
This tool is somewhat useless without rich and reliable signature database. I will be very grateful for any kind of help in the database development.

Contact
-------
To send questions and comments, just send an e-mail at [marcin@ulikowski.pl](mailto:marcin@ulikowski.pl)

* LinkedIn: [Marcin Ulikowski](https://pl.linkedin.com/in/elceef)
* Twitter: [@elceef](https://twitter.com/elceef)

Demo
----
```
elceef@cerebellum:~/dhcpf% sudo ./dhcpf eth1
=== dhcpf 0.7c: passive DHCP fingerprinting ===

Successfully loaded 29 DHCP-prints.

Discover from Motorola_03:e3:1d (40:fc:89:03:e3:1d)
  system	= Android 2.2 (Motorola)

Request from Motorola_03:e3:1d (40:fc:89:03:e3:1d)
  system	= Android 2.2 (Motorola)
  req_ipaddr	= 10.1.1.223

Request from UnknownOUI_58:ab:d5 (d8:31:cf:58:ab:d5)
  system	= Android 2.3 (Samsung)
  req_ipaddr	= 10.1.1.209

Request from FujitsuS_d2:38:de (00:30:05:d2:38:de)
  system	= Windows XP/Vista/7 (generic)
  hostname	= DRI-Stacja
  req_ipaddr	= 10.1.1.115

Discover from CiscoLin_db:d5:36 (00:0e:08:db:d5:36)
  system	= Linksys SipuraSPA
  hostname	= SipuraSPA
  req_ipaddr	= 10.2.2.4
  option82	= remote_id 70:72:cf:59:0d:35 circuit_id vlan 504 unit 1 port 1

Request from CiscoLin_db:d5:36 (00:0e:08:db:d5:36)
  system	= Linksys SipuraSPA
  hostname	= SipuraSPA
  req_ipaddr	= 10.2.2.4
  option82	= remote_id 70:72:cf:59:0d:35 circuit_id vlan 504 unit 1 port 1
```
