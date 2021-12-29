package main

import (
	"encoding/binary"
	"net"
)

type BackendServerKey struct {
	ServerID uint32
}

func (bsk *BackendServerKey) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, bsk.ServerID)
	return buf, nil
}

func (bsk *BackendServerKey) UnmarshalBinary(buf []byte) error {
	bsk.ServerID = binary.BigEndian.Uint32(buf)
	return nil
}

type BackendServer struct {
	Addr    uint32
	Port    uint16
	Padding uint16
}

func (bs *BackendServer) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf, bs.Addr)
	binary.BigEndian.PutUint16(buf[4:], bs.Port)
	binary.BigEndian.PutUint16(buf[6:], bs.Padding)
	return buf, nil
}

func (bs *BackendServer) UnmarshalBinary(buf []byte) error {
	bs.Addr = binary.BigEndian.Uint32(buf)
	bs.Port = binary.BigEndian.Uint16(buf[4:])
	bs.Padding = binary.BigEndian.Uint16(buf[6:])
	return nil
}

func IP2Uint32(ipStr string) uint32 {
	return binary.BigEndian.Uint32(net.ParseIP(ipStr).To4())
}
