package pcapng

import (
	"fmt"

	"io"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// To convert from pcapng to pcap use:
// editcap.exe -F pcap many_interfaces.pcapng many_interfaces.pcap
// or
// tshark -F pcap -r file.pcapng -w file.pcap

// Example files from:
// 1. https://wiki.wireshark.org/Development/PcapNg
// 2. https://github.com/hadrielk/pcapng-test-generator

func TestGood(t *testing.T) {
	files := []string{
		"dhcp", //dhcp.pcapng (SHB, IDB, 4 * EPB)
		"dhcp_big_endian",
		"dhcp_little_endian",
	}
	for _, name := range files {
		t.Run(name, func(t *testing.T) {
			pcapNgFile, _ := os.Open(fmt.Sprintf("test_files/%s.pcapng", name))
			defer pcapNgFile.Close()
			pcapNgReader, err := NewReader(pcapNgFile)
			if err != nil {
				t.Errorf("Error to create pcapng reader: %s", err)
				return
			}

			pcapFile, _ := os.Open(fmt.Sprintf("test_files/%s.pcap", name))
			defer pcapFile.Close()
			pcapReader, err := pcapgo.NewReader(pcapFile)
			if err != nil {
				t.Errorf("Error to create pcap reader for file: %s", err)
				return
			}

			if pcapNgReader.LinkType() != pcapReader.LinkType() {
				t.Errorf("Link type mismatch. PcapNg=%d, Pcap=%d", pcapNgReader.LinkType(), pcapReader.LinkType())
				return
			}

			packetsInfo := make([]packetInfo, 0)
			for i := 1; ; i++ {
				pcapNgData, pcapNgCi, pcapNgErr := pcapNgReader.ReadPacketData()
				packetsInfo = append(packetsInfo, packetInfo{pcapNgReader.bh.Type, pcapNgData, pcapNgCi})
				pcapData, pcapCi, pcapErr := pcapReader.ReadPacketData()
				switch {
				case pcapNgErr == io.EOF && pcapErr == io.EOF:
					return
				case pcapNgErr == ErrPerPacketEncap:
					t.Error(pcapNgErr)
					printInterfacesInfo(pcapNgReader, t)
					printPacketsInfo(packetsInfo, t)
					t.FailNow()
				case pcapNgErr != nil:
					t.Error(pcapNgErr)
					return
				}

				if !reflect.DeepEqual(pcapNgData, pcapData) {
					t.Errorf("Packet %d. Data is not equal.\n\tpcapNgData=%+v\n\tpcapData=  %+v", i, pcapNgData, pcapData)
					t.Fail()
				}
				pcapNgCi.Timestamp = pcapNgCi.Timestamp.In(time.UTC)
				pcapNgCi.InterfaceIndex = 0 // need as pcap does not have this field
				if !reflect.DeepEqual(pcapNgCi, pcapCi) {
					t.Errorf("Packet %d. Capture Info is not equal.\n\tpcapNgCi=%+v\n\tpcapCi  =%+v", i, pcapNgCi, pcapCi)
					t.Fail()
				}
			}
		})
	}

}

func TestEncapPerPacket(t *testing.T) {
	files := []string{
		"many_interfaces",
		"be_advanced_test100",
		"be_advanced_test101",
	}

	packets := make([]packetInfo, 0)
	for _, name := range files {
		t.Run(name, func(t *testing.T) {
			pcapNgFile, _ := os.Open(fmt.Sprintf("test_files/%s.pcapng", name))
			defer pcapNgFile.Close()
			pcapNgReader, err := NewReader(pcapNgFile)
			if err != nil {
				t.Errorf("Error to create pcapng reader: %s", err)
				return
			}

			for i := 1; ; i++ {
				data, ci, pcapNgErr := pcapNgReader.ReadPacketData()
				packets = append(packets, packetInfo{pcapNgReader.bh.Type, data, ci})
				if pcapNgErr == ErrPerPacketEncap {
					return
				}
				if pcapNgErr != nil {
					t.Errorf("Must return ErrPerPacketEncap, but has %s", pcapNgErr)
					printInterfacesInfo(pcapNgReader, t)
					printPacketsInfo(packets, t)
					return
				}
			}

		})
	}
}

type packetInfo struct {
	name uint32
	data []byte
	ci   gopacket.CaptureInfo
}

func printPacketsInfo(packets []packetInfo, t *testing.T) {
	for _, info := range packets {
		t.Logf("%s, CaptureInfo: %+v\n", blockName(info.name), info.ci)
	}

}

func printInterfacesInfo(r *Reader, t *testing.T) {
	for i, shb := range r.listSHB {
		t.Logf("SHB #%d", i)
		for j, idb := range shb.listIDB {
			t.Logf("\tInterface #%d: %+v", j, idb)
		}
	}
}
