package main

import (
	"encoding/binary"
	"net"
)

type BackendServer struct {
	Addr uint32
	Port uint16
}

func (bs *BackendServer) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 6)
	binary.BigEndian.PutUint32(buf, bs.Addr)
	binary.BigEndian.PutUint16(buf[4:], bs.Port)
	return buf, nil
}

func (bs *BackendServer) UnmarshalBinary(buf []byte) error {
	bs.Addr = binary.BigEndian.Uint32(buf)
	bs.Port = binary.BigEndian.Uint16(buf[4:])
	return nil
}

func IP2Uint32(ipStr string) uint32 {
	return binary.BigEndian.Uint32(net.ParseIP(ipStr).To4())
}

