// Send UDP packets to multiple addresses
// Copyright (C) 2017 Diego Fernández Barrera
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"encoding/binary"
	"net"

	"github.com/Bigomby/gopiper/component"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

const (
	udpProto     = 0x11
	udpHeaderLen = 8
)

type udpHeader struct {
	src  uint16
	dst  uint16
	ulen uint16
	csum uint16
}

// Dummy main
func main() {}

/////////////
// Factory //
/////////////

// Factory is used to create instances of multiudp component
type Factory struct {
	workers     int
	channelSize int
	addressList []string
}

// NewFactory creates a new factory for the multiudp component
func NewFactory() component.Factory {
	return &Factory{workers: 1, channelSize: 10}
}

// Create is the method that creates initialized instances of multiudp component
func (f *Factory) Create(out chan component.Message) component.Component {
	component := &Component{}

	for _, addr := range f.addressList {
		component.addresses = append(component.addresses, net.ParseIP(addr))
	}

	return component
}

// Destroy closes resources associated to the Factory
func (f Factory) Destroy() {}

// PoolSize returns the size of the worker pool
func (f Factory) PoolSize() int { return f.workers }

// ChannelSize returns the size of the output channel
func (f Factory) ChannelSize() int { return f.channelSize }

// SetAttribute allows to set attributes to the components after they are
// created
func (f *Factory) SetAttribute(key string, value interface{}) error {
	switch key {
	case "address_list":
		for _, address := range value.(map[string]interface{}) {
			f.addressList = append(f.addressList, address.(string))
		}
	}

	return nil
}

///////////////
// Component //
///////////////

// Component handles UDP packets
type Component struct {
	addresses []net.IP
}

// Handle receives a Payload and send it in a raw UDP/IP packet keeping the
// original source IP and UDP src/dst ports
func (c Component) Handle(msg component.Message) *component.Report {
	var err error

	packet := msg.GetData().(gopacket.Packet)
	srcIP := net.ParseIP(msg.GetAttribute("src_ip").(string))
	udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok {
		return &component.Report{
			Status:      component.Drop,
			Description: "No UDP packet received",
		}
	}

	for _, dstIP := range c.addresses {
		var data []byte
		data, err = craftRawPacket(
			udp.Payload, srcIP, dstIP, uint16(udp.SrcPort), uint16(udp.DstPort),
		)
		if err != nil {
			return &component.Report{Status: component.Fail, Description: err.Error()}
		}

		raddr, err := net.ResolveIPAddr("ip", dstIP.String())
		if err != nil {
			return &component.Report{Status: component.Fail, Description: err.Error()}
		}

		conn, err := net.DialIP("ip:udp", nil, raddr)
		if err != nil {
			return &component.Report{Status: component.Fail, Description: err.Error()}
		}
		defer conn.Close()

		rconn, err := ipv4.NewRawConn(conn)
		if err != nil {
			return &component.Report{Status: component.Fail, Description: err.Error()}
		}

		if _, err := rconn.Write(data); err != nil {
			return &component.Report{Status: component.Fail, Description: err.Error()}
		}
	}

	return &component.Report{Status: component.Done}
}

///////////
// Utils //
///////////

func craftRawPacket(
	payload []byte,
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
) ([]byte, error) {
	buf := &bytes.Buffer{}

	udpH := udpHeader{
		src:  srcPort,
		dst:  dstPort,
		ulen: uint16(udpHeaderLen + len(payload)),
	}

	ipH := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TOS:      0x00,
		TotalLen: ipv4.HeaderLen + int(udpH.ulen),
		TTL:      64,
		Protocol: udpProto,
		Src:      srcIP,
		Dst:      dstIP,
	}

	ipHeaderBytes, err := ipH.Marshal()
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.BigEndian, &ipHeaderBytes)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.BigEndian, &udpH)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.BigEndian, &payload)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
