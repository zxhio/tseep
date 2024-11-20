package packet

import (
	"bytes"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Formatter interface {
	Format([]DecodingLayer) ([]byte, error)
}

func Format(layerList []DecodingLayer) ([]byte, error) {
	f := formatter{}
	err := f.format(layerList)
	if err != nil {
		return nil, err
	}
	return f.Bytes(), nil
}

// like tcpdump
type formatter struct {
	vxlanDepth int
	bytes.Buffer
}

func (f *formatter) format(layerList []DecodingLayer) error {
	if len(layerList) == 0 {
		return nil
	}

	eth, ok := layerList[0].(*layers.Ethernet)
	if !ok {
		return fmt.Errorf("1st layer is not ethernet")
	}
	f.formatEthernet(eth)

	var (
		layer     DecodingLayer
		layerType gopacket.LayerType
	)

	layerType = eth.NextLayerType()
	for i := 1; i < len(layerList); i++ {
		layer = layerList[i]
		err := f.formatLayer(layerList[i-1], layerType, layer)
		if err != nil {
			return err
		}
		layerType = layer.NextLayerType()
	}
	return nil
}

func (f *formatter) formatLayer(underLayer DecodingLayer, layerType gopacket.LayerType, layer DecodingLayer) error {
	switch layerType {
	case layers.LayerTypeEthernet:
		f.formatEthernet(layer.(*layers.Ethernet))
	case layers.LayerTypeARP:
		f.formatARP(layer.(*layers.ARP))
	case layers.LayerTypeDot1Q:
		f.formatVLAN(layer.(*layers.Dot1Q))
	case layers.LayerTypeIPv4:
		f.formatIPv4(layer.(*layers.IPv4))
	case layers.LayerTypeTCP:
		ipv4, ok := underLayer.(*layers.IPv4)
		if !ok {
			return fmt.Errorf("the underlying layer of TCP is not IPv4")
		}
		f.formatTCP(ipv4, layer.(*layers.TCP))
	case layers.LayerTypeICMPv4:
		ipv4, ok := underLayer.(*layers.IPv4)
		if !ok {
			return fmt.Errorf("the underlying layer of TCP is not IPv4")
		}
		f.formatICMP(ipv4, layer.(*layers.ICMPv4))
	case layers.LayerTypeUDP:
		ipv4, ok := underLayer.(*layers.IPv4)
		if !ok {
			return fmt.Errorf("the underlying layer of TCP is not IPv4")
		}
		f.formatUDP(ipv4, layer.(*layers.UDP))
	case layers.LayerTypeVXLAN:
		f.formatVXLAN(layer.(*layers.VXLAN))
	}
	return nil
}

func (f *formatter) formatEthernet(layer *layers.Ethernet) {
	f.WriteString(fmt.Sprintf("%s > %s, ethertype %s (0x%04x), length %d",
		layer.SrcMAC, layer.DstMAC, layer.EthernetType, int(layer.EthernetType), len(layer.Contents)+len(layer.Payload)))
}

func (f *formatter) formatARP(layer *layers.ARP) {
	f.WriteString(": ARP, ")
	if layer.Operation == layers.ARPRequest {
		f.WriteString(fmt.Sprintf("Request who-has %s tell %s", net.IP(layer.DstProtAddress), net.IP(layer.SourceProtAddress)))
	} else if layer.Operation == layers.ARPReply {
		f.WriteString(fmt.Sprintf("Reply %s is-at %s", net.IP(layer.DstProtAddress), net.HardwareAddr(layer.DstHwAddress)))
	}
	f.WriteString(fmt.Sprintf(", length %d", len(layer.Payload)+len(layer.Contents)))
}

func (f *formatter) formatVLAN(layer *layers.Dot1Q) {
	f.WriteString(fmt.Sprintf(": vlan %d ethertype %s (0x%04x)", layer.VLANIdentifier, layer.Type, int(layer.Type)))
}

func (f *formatter) formatIPv4(layer *layers.IPv4) {}

func (f *formatter) formatTCP(ipv4 *layers.IPv4, tcp *layers.TCP) {
	f.WriteString(fmt.Sprintf(", %s.%d > %s.%d: Flags [%s], length %d",
		ipv4.SrcIP, tcp.SrcPort, ipv4.DstIP, tcp.DstPort, stringifyTCPFlags(tcp), len(tcp.Payload)))
}

func (f *formatter) formatICMP(ipv4 *layers.IPv4, icmp *layers.ICMPv4) {
	f.WriteString(fmt.Sprintf(", %s > %s: ICMP %s, id %d, req %d, length %d",
		ipv4.SrcIP, ipv4.DstIP, icmp.TypeCode, icmp.Id, icmp.Seq, len(icmp.Contents)+len(icmp.Payload)))
}

func (f *formatter) formatUDP(ipv4 *layers.IPv4, udp *layers.UDP) {
	f.WriteString(fmt.Sprintf(", %s.%d > %s.%d", ipv4.SrcIP, udp.SrcPort, ipv4.DstIP, udp.DstPort))
	if udp.NextLayerType() == gopacket.LayerTypePayload {
		f.WriteString(fmt.Sprintf(": UDP, length %d", len(udp.Payload)))
	}
}

func (f *formatter) formatVXLAN(layer *layers.VXLAN) {
	f.WriteString(fmt.Sprintf(": VXLAN, vni %d\n", layer.VNI))
	f.vxlanDepth++
	for i := 0; i < f.vxlanDepth; i++ {
		f.WriteByte(' ')
	}
	f.WriteString("└ ")
}

func stringifyTCPFlags(layer *layers.TCP) string {
	var s string
	if layer.SYN {
		s = "S"
	} else if layer.PSH {
		s = "P"
	} else if layer.FIN {
		s = "F"
	} else if layer.RST {
		s = "R"
	}
	if layer.ACK {
		s += "."
	}
	return s
}
