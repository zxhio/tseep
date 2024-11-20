package capture

import (
	"encoding/binary"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// Both openRawSock and htons are available in
// https://github.com/cilium/ebpf/blob/master/example_sock_elf_test.go.
// MIT license.

func OpenRawSocket(ifIndex int) (int, error) {
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return 0, errors.Wrap(err, "syscall.Socket")
	}

	err = syscall.Bind(sock, &syscall.SockaddrLinklayer{Ifindex: ifIndex, Protocol: htons(syscall.ETH_P_ALL)})
	if err != nil {
		syscall.Close(sock)
		return 0, errors.Wrap(err, "syscall.Bind")
	}
	return sock, nil
}

func SetPacketRxRing(fd int, tPacketReq *unix.TpacketReq) error {
	return unix.SetsockoptTpacketReq(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, tPacketReq)
}

// Set socket level PROMISC mode
func SetPacketMembership(fd int, ifIndex int32) error {
	return unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &unix.PacketMreq{Type: unix.PACKET_MR_PROMISC, Ifindex: ifIndex})
}

// Enable PACKET_AUXDATA option for VLAN
func SetPacketAuxData(fd int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_PACKET, unix.PACKET_AUXDATA, 1)
}

// htons converts the unsigned short integer hostshort from host byte order to network byte order.
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
