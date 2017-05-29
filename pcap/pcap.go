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
	"sync"
	"time"

	"github.com/Bigomby/gopiper/component"
	"github.com/Bigomby/gopiper/messages"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Dummy main
func main() {}

///////////////
// Component //
///////////////

// Component is a component for capturing packets
type Component struct{}

// Handle does nothing since this component is the first component on the
// pipeline
func (c *Component) Handle(component.Message) *component.Report { return nil }

/////////////
// Factory //
/////////////

// Factory is used to create instances of stdin component
type Factory struct {
	device      string
	filter      string
	channelSize int
	terminate   chan struct{}

	wg *sync.WaitGroup
}

// NewFactory creates a new factory for the gopacket component
func NewFactory() component.Factory {
	return &Factory{
		terminate:   make(chan struct{}),
		channelSize: 10,
		wg:          &sync.WaitGroup{},
	}
}

// Create is the method that creates instances of gopacket component. It spawns
// a gorutine for capturing packets from network.
func (f *Factory) Create(out chan component.Message) component.Component {
	var err error

	handle, err := pcap.OpenLive(f.device, 65536, false, 100*time.Millisecond)
	if err != nil {
		panic(err)
	}

	err = handle.SetBPFFilter(f.filter)
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	f.wg.Add(1)
	go func() {
		defer handle.Close()

	loop:
		for {
			select {
			case <-f.terminate:
				break loop

			case packet := <-packetSource.Packets():
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				if ipLayer == nil {
					continue
				}

				msg := messages.NewInterfaceMessage()
				msg.SetAttribute("src_ip", ipLayer.(*layers.IPv4).SrcIP.String())
				msg.SetData(packet)
				out <- msg
			}
		}

		f.wg.Done()
	}()

	return &Component{}
}

// Destroy closes resources associated to the Factory
func (f *Factory) Destroy() {
	close(f.terminate)
	f.wg.Wait()
}

// PoolSize returns the size of the worker pool
func (f Factory) PoolSize() int { return 1 }

// ChannelSize returns the size of the output channel
func (f Factory) ChannelSize() int { return f.channelSize }

// SetAttribute allows to set attributes to the components created with the
// Create() method
func (f *Factory) SetAttribute(key string, value interface{}) error {
	switch key {
	case "device":
		f.device = value.(string)

	case "filter":
		f.filter = value.(string)
	}

	return nil
}
