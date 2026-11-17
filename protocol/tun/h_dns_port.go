package tun

// dnsPacketPort says whether a datagram to the TUN's DNS address, to this port, is a DNS query.
// Only port 53 is: the TUN's DNS server is a plain DNS server, and any app can send a datagram to
// another port of its address. Upstream took every datagram to the address as DNS, logged an
// error for each one that did not parse (an app could fill the log and the problem reports with
// them) and never routed it. Such a datagram now goes through the routing rules like any other.
func dnsPacketPort(port uint16) bool {
	return port == 53
}
