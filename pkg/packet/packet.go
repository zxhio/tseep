package packet

import (
	"github.com/google/gopacket/layers"
)

type PacketEthernet struct {
	VXLAN *PacketVXLAN
	*layers.Ethernet
}

type PacketARP struct {
	Ethernet *PacketEthernet
	*layers.ARP
}

type PacketVLAN struct {
	Ethernet *PacketEthernet
	*layers.Dot1Q
}

type PacketIPv4 struct {
	VLAN *PacketVLAN
	*layers.IPv4
}

type PacketTCP struct {
	IPv4 *PacketIPv4
	*layers.TCP
}

type PacketICMP struct {
	IPv4 *PacketIPv4
	*layers.ICMPv4
}

type PacketUDP struct {
	IPv4 *PacketIPv4
	*layers.UDP
}

type PacketVXLAN struct {
	UDP *PacketUDP
	*layers.VXLAN
}
