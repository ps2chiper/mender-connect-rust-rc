// Live dispatch errors only: production Mender binary candidates must be absent.
package main

import (
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/mendersoftware/go-lib-micro/ws"
	mc "github.com/mendersoftware/go-lib-micro/ws/menderclient"
	"github.com/vmihailenco/msgpack/v5"
	"os"
	"path/filepath"
	"strings"
)

func menderPeer(c *websocket.Conn, dir, scenario string) ([]string, error) {
	for _, binary := range []string{"/usr/bin/mender-update", "/usr/bin/mender"} {
		if _, err := os.Stat(binary); !os.IsNotExist(err) {
			return nil, fmt.Errorf("refusing live-command test when production candidate exists: %s", binary)
		}
	}
	p := &peer{c: c, proto: ws.ProtoTypeControl}
	if err := p.request("open", "capabilities", ws.Open{Versions: []int{1}}); err != nil {
		return nil, err
	}
	m, err := p.expect("accept", "capabilities")
	if err != nil {
		return nil, err
	}
	var accept ws.Accept
	if err = msgpack.Unmarshal(m.Body, &accept); err != nil {
		return nil, err
	}
	present := false
	for _, proto := range accept.Protocols {
		present = present || proto == ws.ProtoTypeMenderClient
	}
	disabled := scenario == "mender-disabled"
	if present == disabled {
		return nil, fmt.Errorf("command capability mismatch %v", accept.Protocols)
	}
	marker := filepath.Join(dir, "must-not-exist")
	p.proto = ws.ProtoTypeMenderClient
	for _, request := range []struct{ typ, sid string }{{mc.MessageTypeMenderClientCheckUpdate, ""}, {mc.MessageTypeMenderClientSendInventory, "command-session"}, {"unknown-command", "unknown"}, {mc.MessageTypeMenderClientCheckUpdate, "reused"}, {mc.MessageTypeMenderClientSendInventory, "reused"}} {
		body := []byte("; touch " + marker + "; $(touch " + marker + ")")
		if err = p.send(request.typ, request.sid, body, nil); err != nil {
			return nil, err
		}
		m, err = p.expect(request.typ, request.sid)
		if err != nil {
			return nil, err
		}
		if fmt.Sprint(m.Header.Properties["status"]) != "2" || len(m.Body) == 0 {
			return nil, fmt.Errorf("command error schema mismatch %+v", m.Header)
		}
		if disabled && !strings.Contains(strings.ToLower(string(m.Body)), "disabled") {
			return nil, fmt.Errorf("disabled command not identified")
		}
		if _, err = os.Stat(marker); !os.IsNotExist(err) {
			return nil, fmt.Errorf("untrusted command body executed")
		}
	}
	p.proto = ws.ProtoTypeControl
	if err = p.send("ping", "still-connected", nil, nil); err != nil {
		return nil, err
	}
	if _, err = p.expect("pong", "still-connected"); err != nil {
		return nil, err
	}
	return []string{"Mender command capability follows disable switch", "allowlisted/unknown command failures use upstream status2 response", "empty SID and repeated requests handled without losing replies", "body injection ignored and websocket remains usable", "no installed Mender binary was executed"}, nil
}
