// Code generated by bpf2go; DO NOT EDIT.
//go:build mips || mips64 || ppc64 || s390x

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type packet_inspector_kernPacketInfo struct {
	SrcIp   uint32
	DstIp   uint32
	SrcPort uint16
	DstPort uint16
	Length  uint16
	_       [2]byte
}

// loadPacket_inspector_kern returns the embedded CollectionSpec for packet_inspector_kern.
func loadPacket_inspector_kern() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Packet_inspector_kernBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load packet_inspector_kern: %w", err)
	}

	return spec, err
}

// loadPacket_inspector_kernObjects loads packet_inspector_kern and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*packet_inspector_kernObjects
//	*packet_inspector_kernPrograms
//	*packet_inspector_kernMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadPacket_inspector_kernObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadPacket_inspector_kern()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// packet_inspector_kernSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type packet_inspector_kernSpecs struct {
	packet_inspector_kernProgramSpecs
	packet_inspector_kernMapSpecs
}

// packet_inspector_kernSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type packet_inspector_kernProgramSpecs struct {
	XdpPacketInspector *ebpf.ProgramSpec `ebpf:"xdp_packet_inspector"`
}

// packet_inspector_kernMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type packet_inspector_kernMapSpecs struct {
	PacketMap *ebpf.MapSpec `ebpf:"packet_map"`
}

// packet_inspector_kernObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadPacket_inspector_kernObjects or ebpf.CollectionSpec.LoadAndAssign.
type packet_inspector_kernObjects struct {
	packet_inspector_kernPrograms
	packet_inspector_kernMaps
}

func (o *packet_inspector_kernObjects) Close() error {
	return _Packet_inspector_kernClose(
		&o.packet_inspector_kernPrograms,
		&o.packet_inspector_kernMaps,
	)
}

// packet_inspector_kernMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadPacket_inspector_kernObjects or ebpf.CollectionSpec.LoadAndAssign.
type packet_inspector_kernMaps struct {
	PacketMap *ebpf.Map `ebpf:"packet_map"`
}

func (m *packet_inspector_kernMaps) Close() error {
	return _Packet_inspector_kernClose(
		m.PacketMap,
	)
}

// packet_inspector_kernPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadPacket_inspector_kernObjects or ebpf.CollectionSpec.LoadAndAssign.
type packet_inspector_kernPrograms struct {
	XdpPacketInspector *ebpf.Program `ebpf:"xdp_packet_inspector"`
}

func (p *packet_inspector_kernPrograms) Close() error {
	return _Packet_inspector_kernClose(
		p.XdpPacketInspector,
	)
}

func _Packet_inspector_kernClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed packet_inspector_kern_bpfeb.o
var _Packet_inspector_kernBytes []byte
