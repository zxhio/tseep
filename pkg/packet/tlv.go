package packet

import "tseep/pkg/tlv"

type PacketTLV struct {
	tlv.TLV
	Data []byte
}
