// Reviewer-only soak: compiled with private copies of the upstream-schema peers.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/mendersoftware/go-lib-micro/ws"
	ft "github.com/mendersoftware/go-lib-micro/ws/filetransfer"
	pf "github.com/mendersoftware/go-lib-micro/ws/portforward"
	"github.com/vmihailenco/msgpack/v5"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func soakSeconds() int {
	n, err := strconv.Atoi(os.Getenv("SOAK_SECONDS"))
	if err != nil || n < 30 || n > 3600 {
		return 2700
	}
	return n
}

func soakScheme() string {
	if os.Getenv("SOAK_TLS_CERT") != "" {
		return "https://"
	}
	return "http://"
}

func soakForward(p *peer, proto ws.ProtoType, network string) error {
	p.proto, p.cid = proto, "reused-socket"
	defer func() { p.cid = "" }()
	var port uint16
	var accepted chan net.Conn
	done := make(chan struct{})
	var tcp net.Listener
	var udp *net.UDPConn
	var server net.Conn
	if network == "tcp" {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		tcp, port = listener, uint16(listener.Addr().(*net.TCPAddr).Port)
		defer tcp.Close()
		accepted = make(chan net.Conn, 1)
		go func() {
			defer close(done)
			c, e := listener.Accept()
			if e != nil {
				return
			}
			defer c.Close()
			accepted <- c
			c.SetDeadline(time.Now().Add(8 * time.Second))
			io.Copy(c, c)
		}()
	} else {
		socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			return err
		}
		udp, port = socket, uint16(socket.LocalAddr().(*net.UDPAddr).Port)
		defer udp.Close()
		go func() {
			defer close(done)
			buffer := make([]byte, 4096)
			for {
				n, addr, e := socket.ReadFromUDP(buffer)
				if e != nil {
					return
				}
				if _, e = socket.WriteToUDP(buffer[:n], addr); e != nil {
					return
				}
			}
		}()
	}
	host := "127.0.0.1"
	protocol := pf.PortForwardProtocol(network)
	if err := p.request("new", "reused-forward", pf.PortForwardNew{RemoteHost: &host, RemotePort: &port, Protocol: &protocol}); err != nil {
		return err
	}
	if _, err := p.expect("new", "reused-forward"); err != nil {
		return err
	}
	if tcp != nil {
		select {
		case server = <-accepted:
			defer server.Close()
		case <-time.After(3 * time.Second):
			return fmt.Errorf("soak target accept timeout")
		}
	}
	inputs := [][]byte{bytes.Repeat([]byte{0, 255, 128, 7}, 128)}
	if udp != nil {
		inputs = append(inputs, []byte{})
	}
	for _, input := range inputs {
		if err := p.send("forward", "reused-forward", input, nil); err != nil {
			return err
		}
		var got []byte
		sawForward := false
		acked := proto == ws.ProtoTypePortForwardV2
		for !sawForward || len(got) < len(input) || !acked {
			m, err := p.next()
			if err != nil {
				return err
			}
			if m.Header.Proto != proto || m.Header.SessionID != "reused-forward" || m.Header.Properties[pf.PropertyConnectionID] != p.cid {
				return fmt.Errorf("soak forwarding crossed identity %+v", m.Header)
			}
			switch m.Header.MsgType {
			case "ack":
				if acked {
					return fmt.Errorf("duplicate forwarding ACK")
				}
				acked = true
			case "forward":
				sawForward = true
				got = append(got, m.Body...)
				if proto == ws.ProtoTypePortForward {
					if err = p.send("ack", "reused-forward", nil, nil); err != nil {
						return err
					}
				}
			default:
				return fmt.Errorf("unexpected forwarding type %s", m.Header.MsgType)
			}
		}
		if !bytes.Equal(got, input) {
			return fmt.Errorf("soak %s echo differs", network)
		}
	}
	if err := p.send("stop", "reused-forward", nil, nil); err != nil {
		return err
	}
	if _, err := p.expect("stop", "reused-forward"); err != nil {
		return err
	}
	if udp != nil {
		udp.Close()
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		return fmt.Errorf("soak target not closed on stop")
	}
	return nil
}

func soakCheckpoint(dir string, cycle int, elapsed float64, counts map[string]int) error {
	data, err := json.Marshal(map[string]interface{}{"cycle": cycle, "elapsed_seconds": elapsed, "counts": counts})
	if err != nil {
		return err
	}
	marker := filepath.Join(dir, "quiescent.ready")
	if err = os.WriteFile(marker+".tmp", data, 0600); err != nil {
		return err
	}
	if err = os.Rename(marker+".tmp", marker); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ack, e := os.ReadFile(filepath.Join(dir, "quiescent.ack"))
		if e == nil && strings.TrimSpace(string(ack)) == strconv.Itoa(cycle) {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("resource monitor did not acknowledge quiescent cycle %d", cycle)
}

func runSoak(c *websocket.Conn, dir string) ([]string, error) {
	p := &peer{c: c, proto: ws.ProtoTypeFileTransfer}
	if err := p.handshake(false); err != nil {
		return nil, err
	}
	assets := filepath.Join(dir, "assets")
	files := filepath.Join(assets, "files")
	mixed := filepath.Join(assets, "mixed")
	for _, path := range []string{files, mixed} {
		if err := os.MkdirAll(path, 0700); err != nil {
			return nil, err
		}
	}
	path := filepath.Join(files, "fixture.bin")
	mixedPath := filepath.Join(mixed, "fixture.bin")
	payload := bytes.Repeat([]byte{0, 255, 128, 42, 1, 0, 7}, 23000)
	counts := map[string]int{"uploads": 0, "downloads": 0, "stats": 0, "forward_connections": 0, "mixed_closes": 0, "zero_udp": 0}
	started := time.Now()
	deadline := started.Add(time.Duration(soakSeconds()) * time.Second)
	cycle := 0
	for time.Now().Before(deadline) {
		cycleStarted := time.Now()
		cycle++
		for _, proto := range []ws.ProtoType{ws.ProtoTypeFileTransfer, ws.ProtoTypeFileTransferV2} {
			p.proto, p.cid = proto, ""
			if err := p.upload(path, "reused-file", payload); err != nil {
				return nil, fmt.Errorf("cycle%d upload proto%d: %w", cycle, proto, err)
			}
			counts["uploads"]++
			if err := p.download(path, "reused-file", payload); err != nil {
				return nil, fmt.Errorf("cycle%d download proto%d: %w", cycle, proto, err)
			}
			counts["downloads"]++
			if err := p.request("stat", "reused-file", ft.StatFile{Path: &path}); err != nil {
				return nil, err
			}
			info, err := p.expect("file_info", "reused-file")
			if err != nil {
				return nil, err
			}
			var metadata ft.FileInfo
			if err = msgpack.Unmarshal(info.Body, &metadata); err != nil {
				return nil, err
			}
			if metadata.Size == nil || *metadata.Size != int64(len(payload)) {
				return nil, fmt.Errorf("stat size differs")
			}
			counts["stats"]++
			if cycle%5 == 0 {
				if err := p.upload(path, "reused-file", nil); err != nil {
					return nil, err
				}
				counts["uploads"]++
				if err := p.download(path, "reused-file", nil); err != nil {
					return nil, err
				}
				counts["downloads"]++
			}
		}
		for _, proto := range []ws.ProtoType{ws.ProtoTypePortForward, ws.ProtoTypePortForwardV2} {
			for _, network := range []string{"tcp", "udp"} {
				if err := soakForward(p, proto, network); err != nil {
					return nil, fmt.Errorf("cycle%d %s proto%d: %w", cycle, network, proto, err)
				}
				counts["forward_connections"]++
				if network == "udp" {
					counts["zero_udp"]++
				}
			}
		}
		if _, err := mixedClose(p, mixed, mixedPath); err != nil {
			return nil, fmt.Errorf("cycle%d mixed close: %w", cycle, err)
		}
		counts["mixed_closes"]++
		counts["forward_connections"] += 2
		p.proto, p.cid = ws.ProtoTypeControl, ""
		if err := p.send("ping", "soak-cleanup-barrier", nil, nil); err != nil {
			return nil, err
		}
		if _, err := p.expect("pong", "soak-cleanup-barrier"); err != nil {
			return nil, err
		}
		counts["shell_interleaves"] = p.shellDrained
		if err := soakCheckpoint(dir, cycle, time.Since(started).Seconds(), counts); err != nil {
			return nil, err
		}
		if remain := time.Second - time.Since(cycleStarted); remain > 0 {
			time.Sleep(remain)
		}
	}
	return []string{fmt.Sprintf("same daemon/WebSocket lifetime %.1fs/%d cycles", time.Since(started).Seconds(), cycle), fmt.Sprintf("validated operations %v", counts), "v1/v2 byte-exact atomic file transfer and immediate key reuse", "real TCP/UDP v1/v2 echo including zero datagrams", "mixed close removes staged file/socket/shell and preserves unrelated socket"}, nil
}
