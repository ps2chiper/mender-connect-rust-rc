// Reviewer-only mixed-protocol lifecycle proof; compiled with fourhour_file_peer.go.
package main

import (
	"bytes"
	"fmt"
	"github.com/mendersoftware/go-lib-micro/ws"
	ft "github.com/mendersoftware/go-lib-micro/ws/filetransfer"
	pf "github.com/mendersoftware/go-lib-micro/ws/portforward"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func mixedClose(p *peer, assets, path string) ([]string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 2)
	go func() {
		for i := 0; i < 2; i++ {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			accepted <- c
		}
	}()
	host := "127.0.0.1"
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	network := pf.PortForwardProtocol("tcp")
	connections := []net.Conn{}
	defer func() {
		for _, c := range connections {
			c.Close()
		}
	}()
	for _, sid := range []string{"mixed", "unrelated"} {
		p.proto = ws.ProtoTypePortForwardV2
		p.cid = "socket"
		if err = p.request("new", sid, pf.PortForwardNew{RemoteHost: &host, RemotePort: &port, Protocol: &network}); err != nil {
			return nil, err
		}
		if _, err = p.expect("new", sid); err != nil {
			return nil, err
		}
		select {
		case c := <-accepted:
			connections = append(connections, c)
		case <-time.After(3 * time.Second):
			return nil, fmt.Errorf("TCP accept timeout")
		}
	}
	p.cid = ""
	p.proto = ws.ProtoTypeShell
	if err = p.send("new", "mixed", nil, nil); err != nil {
		return nil, err
	}
	if _, err = p.expect("new", "mixed"); err != nil {
		return nil, err
	}
	p.activeShellSID = "mixed"
	defer func() { p.activeShellSID = "" }()
	forced := os.Getenv("SOAK_FORCE_SHELL_INTERLEAVE") == "1"
	releaseFile := filepath.Join(filepath.Dir(filepath.Dir(assets)), "late.release")
	if forced {
		if err := os.Remove(releaseFile); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	pidfile := filepath.Join(assets, "shell.pid")
	command := fmt.Sprintf("printf '%%s' \"$$\" > '%s'; printf '\\115\\111\\130\\105\\104\\122\\105\\101\\104\\131'\n", pidfile)
	if forced {
		command = strings.TrimSuffix(command, "\n") + fmt.Sprintf("; while [ ! -e '%s' ]; do sleep 0.01; done; printf 'SOAK_LATE'\n", releaseFile)
	}
	if err = p.send("shell", "mixed", []byte(command), nil); err != nil {
		return nil, err
	}
	output := []byte{}
	for !bytes.Contains(output, []byte("MIXEDREADY")) {
		m, e := p.expect("shell", "mixed")
		if e != nil {
			return nil, e
		}
		output = append(output, m.Body...)
	}
	old := []byte("old-atomic-content")
	if err = os.WriteFile(path, old, 0600); err != nil {
		return nil, err
	}
	size := int64(4096)
	p.proto = ws.ProtoTypeFileTransfer
	if err = p.request("put_file", "mixed", ft.UploadRequest{Path: &path, Size: &size}); err != nil {
		return nil, err
	}
	if forced {
		if err = os.WriteFile(releaseFile, []byte("release"), 0600); err != nil {
			return nil, err
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err = p.ack("mixed", 0); err != nil {
		return nil, err
	}
	n := int64(0)
	if err = p.send("file_chunk", "mixed", []byte("partial"), &n); err != nil {
		return nil, err
	}
	if err = p.ack("mixed", 0); err != nil {
		return nil, err
	}
	p.proto = ws.ProtoTypeControl
	if err = p.send("close", "mixed", nil, nil); err != nil {
		return nil, err
	}
	if err = p.send("ping", "cleanup-barrier", nil, nil); err != nil {
		return nil, err
	}
	if _, err = p.expect("pong", "cleanup-barrier"); err != nil {
		return nil, err
	}
	p.activeShellSID = ""
	connections[0].SetReadDeadline(time.Now().Add(time.Second))
	one := make([]byte, 1)
	if _, err = connections[0].Read(one); err != io.EOF {
		return nil, fmt.Errorf("closed session socket remains: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, old) {
		return nil, fmt.Errorf("closed session upload altered destination")
	}
	items, err := os.ReadDir(assets)
	if err != nil {
		return nil, err
	}
	if len(items) != 2 {
		return nil, fmt.Errorf("closed session left staging file: %v", items)
	}
	pid, err := os.ReadFile(pidfile)
	if err != nil {
		return nil, err
	}
	if _, err = os.Stat("/proc/" + string(pid)); !os.IsNotExist(err) {
		return nil, fmt.Errorf("closed session shell PID remains")
	}
	p.proto = ws.ProtoTypePortForwardV2
	p.cid = "socket"
	if err = p.send("forward", "unrelated", []byte("unrelated-alive"), nil); err != nil {
		return nil, err
	}
	connections[1].SetReadDeadline(time.Now().Add(time.Second))
	data := make([]byte, len("unrelated-alive"))
	if _, err = io.ReadFull(connections[1], data); err != nil || string(data) != "unrelated-alive" {
		return nil, fmt.Errorf("unrelated socket was closed: %v", err)
	}
	if err = p.send("stop", "unrelated", nil, nil); err != nil {
		return nil, err
	}
	if _, err = p.expect("stop", "unrelated"); err != nil {
		return nil, err
	}
	return []string{"control close cleans shell, forwarding and staged upload sharing SID", "cleanup finishes before next control pong", "unrelated session remains usable"}, nil
}

func mixedProgress(p *peer, assets, path string) ([]string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer listener.Close()
	go func() {
		c, e := listener.Accept()
		if e == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	host := "127.0.0.1"
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	network := pf.PortForwardProtocol("tcp")
	p.proto = ws.ProtoTypePortForwardV2
	p.cid = "echo"
	if err = p.request("new", "fair-port", pf.PortForwardNew{RemoteHost: &host, RemotePort: &port, Protocol: &network}); err != nil {
		return nil, err
	}
	if _, err = p.expect("new", "fair-port"); err != nil {
		return nil, err
	}
	p.proto = ws.ProtoTypeShell
	p.cid = ""
	if err = p.send("new", "fair-shell", nil, nil); err != nil {
		return nil, err
	}
	if _, err = p.expect("new", "fair-shell"); err != nil {
		return nil, err
	}
	payload := bytes.Repeat([]byte{0, 255, 128, 19}, 2*1024*1024)
	if err = os.WriteFile(path, payload, 0600); err != nil {
		return nil, err
	}
	p.proto = ws.ProtoTypeFileTransferV2
	if err = p.request("get_file", "fair-file", ft.GetFile{Path: &path}); err != nil {
		return nil, err
	}
	p.proto = ws.ProtoTypeShell
	command := []byte("head -c 524288 /dev/zero | tr '\\000' X; printf '\\106\\101\\111\\122\\115\\101\\122\\113\\105\\122'\n")
	if err = p.send("shell", "fair-shell", command, nil); err != nil {
		return nil, err
	}
	sendPing := func() error {
		p.proto = ws.ProtoTypeControl
		p.cid = ""
		return p.send("ping", "fair-control", nil, nil)
	}
	echo := bytes.Repeat([]byte("echo\x00\xff"), 100)
	sendEcho := func() error {
		p.proto = ws.ProtoTypePortForwardV2
		p.cid = "echo"
		return p.send("forward", "fair-port", echo, nil)
	}
	if err = sendPing(); err != nil {
		return nil, err
	}
	if err = sendEcho(); err != nil {
		return nil, err
	}
	fileBytes, pongs, echoes, echoBytes, shellXs := 0, 0, 0, 0, 0
	fileDone, shellDone := false, false
	shellBeforeEOF, portBeforeEOF, controlBeforeEOF := false, false, false
	shellTail := []byte{}
	start := time.Now()
	for !fileDone || !shellDone || pongs < 64 || echoes < 64 {
		m, e := p.next()
		if e != nil {
			return nil, e
		}
		if m.Header.MsgType == "error" {
			return nil, fmt.Errorf("mixed runtime error %+v body=%q", m.Header, m.Body)
		}
		switch m.Header.Proto {
		case ws.ProtoTypeFileTransferV2:
			if m.Header.SessionID != "fair-file" || m.Header.MsgType != "file_chunk" {
				return nil, fmt.Errorf("wrong file identity")
			}
			n, e := offset(m)
			if e != nil {
				return nil, e
			}
			if n != int64(fileBytes) || len(m.Body) > len(payload)-fileBytes || !bytes.Equal(m.Body, payload[fileBytes:fileBytes+len(m.Body)]) {
				return nil, fmt.Errorf("mixed download differs at%d", fileBytes)
			}
			fileBytes += len(m.Body)
			if len(m.Body) == 0 {
				fileDone = true
				if fileBytes != len(payload) {
					return nil, fmt.Errorf("early download EOF")
				}
			}
		case ws.ProtoTypeShell:
			if m.Header.SessionID != "fair-shell" || m.Header.MsgType != "shell" {
				return nil, fmt.Errorf("wrong shell event %+v", m.Header)
			}
			if !fileDone {
				shellBeforeEOF = true
			}
			shellXs += bytes.Count(m.Body, []byte("X"))
			shellTail = append(shellTail, m.Body...)
			if bytes.Contains(shellTail, []byte("FAIRMARKER")) {
				shellDone = true
			}
			if len(shellTail) > 128 {
				shellTail = shellTail[len(shellTail)-128:]
			}
		case ws.ProtoTypePortForwardV2:
			if m.Header.SessionID != "fair-port" || m.Header.MsgType != "forward" || m.Header.Properties[pf.PropertyConnectionID] != "echo" {
				return nil, fmt.Errorf("wrong forwarding event")
			}
			if !fileDone {
				portBeforeEOF = true
			}
			if len(m.Body) > len(echo)-echoBytes || !bytes.Equal(m.Body, echo[echoBytes:echoBytes+len(m.Body)]) {
				return nil, fmt.Errorf("mixed echo differs")
			}
			echoBytes += len(m.Body)
			if echoBytes == len(echo) {
				echoes++
				echoBytes = 0
				if echoes < 64 {
					if err = sendEcho(); err != nil {
						return nil, err
					}
				}
			}
		case ws.ProtoTypeControl:
			if m.Header.SessionID != "fair-control" || m.Header.MsgType != "pong" {
				return nil, fmt.Errorf("wrong control event")
			}
			if !fileDone {
				controlBeforeEOF = true
			}
			pongs++
			if pongs < 64 {
				if err = sendPing(); err != nil {
					return nil, err
				}
			}
		default:
			return nil, fmt.Errorf("unknown mixed protocol %v", m.Header.Proto)
		}
		if time.Since(start) > 15*time.Second {
			return nil, fmt.Errorf("mixed progress deadline exceeded")
		}
		time.Sleep(time.Millisecond)
	}
	if shellXs < 524288 || !shellBeforeEOF || !portBeforeEOF || !controlBeforeEOF {
		return nil, fmt.Errorf("starved source shellBytes%d beforeEOF shell%v port%v control%v", shellXs, shellBeforeEOF, portBeforeEOF, controlBeforeEOF)
	}
	p.proto = ws.ProtoTypeShell
	p.cid = ""
	if err = p.send("stop", "fair-shell", nil, nil); err != nil {
		return nil, err
	}
	for {
		m, e := p.next()
		if e != nil {
			return nil, e
		}
		if m.Header.Proto == ws.ProtoTypeShell && m.Header.MsgType == "stop" {
			break
		}
		if m.Header.Proto != ws.ProtoTypeShell || m.Header.MsgType != "shell" {
			return nil, fmt.Errorf("unexpected stop-drain event")
		}
	}
	p.proto = ws.ProtoTypePortForwardV2
	p.cid = "echo"
	if err = p.send("stop", "fair-port", nil, nil); err != nil {
		return nil, err
	}
	if _, err = p.expect("stop", "fair-port"); err != nil {
		return nil, err
	}
	return []string{"8MiB binary download with simultaneous512KiB PTY output", "64exact TCP binary echoes and64control pongs", "all four sources progress before file EOF under slow reading", "explicit shell/socket cleanup"}, nil
}
