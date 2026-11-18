package main

import (
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/mendersoftware/go-lib-micro/ws"
	"github.com/vmihailenco/msgpack/v5"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStrictActiveShellDemux(t *testing.T) {
	t.Setenv("SOAK_DISABLE_DEMUX", "")
	cases := []struct {
		name, active, sid, typ string
		proto                  ws.ProtoType
		status                 int64
		accept                 bool
	}{
		{"legal-active", "mixed", "mixed", "shell", ws.ProtoTypeShell, 1, true},
		{"foreign-sid", "mixed", "foreign", "shell", ws.ProtoTypeShell, 1, false},
		{"after-close-barrier", "", "mixed", "shell", ws.ProtoTypeShell, 1, false},
		{"error-status", "mixed", "mixed", "shell", ws.ProtoTypeShell, 129, false},
		{"foreign-protocol", "mixed", "mixed", "shell", ws.ProtoTypePortForwardV2, 1, false},
		{"shell-error-type", "mixed", "mixed", "error", ws.ProtoTypeShell, 1, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer c.Close()
				frames := []ws.ProtoMsg{
					{Header: ws.ProtoHdr{Proto: test.proto, MsgType: test.typ, SessionID: test.sid, Properties: map[string]interface{}{"status": test.status}}, Body: []byte("interleaved")},
					{Header: ws.ProtoHdr{Proto: ws.ProtoTypeFileTransfer, MsgType: "ack", SessionID: "mixed", Properties: map[string]interface{}{"offset": int64(0)}}},
				}
				for _, frame := range frames {
					data, err := msgpack.Marshal(frame)
					if err != nil {
						return
					}
					if c.WriteMessage(websocket.BinaryMessage, data) != nil {
						return
					}
				}
			}))
			defer server.Close()
			c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			p := &peer{c: c, proto: ws.ProtoTypeFileTransfer, activeShellSID: test.active}
			message, err := p.expect("ack", "mixed")
			if test.accept {
				if err != nil || message.Header.MsgType != "ack" || p.shellDrained != 1 {
					t.Fatalf("legal route rejected: %v %+v drained%d", err, message.Header, p.shellDrained)
				}
			} else {
				if err == nil || p.shellDrained != 0 {
					t.Fatalf("foreign/error/closed-session frame swallowed: %+v drained%d", message.Header, p.shellDrained)
				}
			}
		})
	}
}

func TestControlPingHeartbeatDuringExpect(t *testing.T) {
	t.Setenv("SOAK_DISABLE_DEMUX", "")
	t.Run("correlated-pong", func(t *testing.T) {
		pongErr := make(chan error, 1)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
			if err != nil {
				pongErr <- err
				return
			}
			defer c.Close()
			c.SetWriteDeadline(time.Now().Add(2 * time.Second))
			frames := []ws.ProtoMsg{
				{Header: ws.ProtoHdr{Proto: ws.ProtoTypeControl, MsgType: "ping", SessionID: "handshake"}},
				{Header: ws.ProtoHdr{Proto: ws.ProtoTypeFileTransfer, MsgType: "ack", SessionID: "mixed", Properties: map[string]interface{}{"offset": int64(0)}}},
			}
			for _, frame := range frames {
				data, err := msgpack.Marshal(frame)
				if err != nil {
					pongErr <- err
					return
				}
				if err := c.WriteMessage(websocket.BinaryMessage, data); err != nil {
					pongErr <- err
					return
				}
			}
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, data, err := c.ReadMessage()
			if err != nil {
				pongErr <- err
				return
			}
			var pong ws.ProtoMsg
			if err := msgpack.Unmarshal(data, &pong); err != nil {
				pongErr <- err
				return
			}
			if pong.Header.Proto != ws.ProtoTypeControl || pong.Header.MsgType != "pong" || pong.Header.SessionID != "handshake" {
				pongErr <- fmt.Errorf("invalid correlated pong %+v", pong.Header)
				return
			}
			pongErr <- nil
		}))
		defer server.Close()
		c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		p := &peer{c: c, proto: ws.ProtoTypeFileTransfer}
		type expectResult struct {
			message ws.ProtoMsg
			err     error
		}
		result := make(chan expectResult, 1)
		go func() {
			message, err := p.expect("ack", "mixed")
			result <- expectResult{message, err}
		}()
		select {
		case r := <-result:
			if r.err != nil {
				t.Fatalf("heartbeat broke expected frame: %v", r.err)
			}
			if r.message.Header.MsgType != "ack" || r.message.Header.SessionID != "mixed" {
				t.Fatalf("unexpected frame %+v", r.message.Header)
			}
			if p.controlPings != 1 || p.controlPongs != 1 {
				t.Fatalf("pings%d pongs%d", p.controlPings, p.controlPongs)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("control ping regression deadlocked")
		}
		select {
		case err := <-pongErr:
			if err != nil {
				t.Fatalf("server pong read failed: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("server did not receive correlated pong")
		}
	})
	t.Run("invalid-control-not-swallowed", func(t *testing.T) {
		cases := []struct {
			name  string
			frame ws.ProtoMsg
		}{
			{"non-ping-control", ws.ProtoMsg{Header: ws.ProtoHdr{Proto: ws.ProtoTypeControl, MsgType: "open", SessionID: "handshake"}}},
			{"ping-with-body", ws.ProtoMsg{Header: ws.ProtoHdr{Proto: ws.ProtoTypeControl, MsgType: "ping", SessionID: "handshake"}, Body: []byte("bad")}},
		}
		for _, test := range cases {
			t.Run(test.name, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
					if err != nil {
						return
					}
					defer c.Close()
					c.SetWriteDeadline(time.Now().Add(2 * time.Second))
					data, err := msgpack.Marshal(test.frame)
					if err != nil {
						return
					}
					c.WriteMessage(websocket.BinaryMessage, data)
				}))
				defer server.Close()
				c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				p := &peer{c: c, proto: ws.ProtoTypeFileTransfer}
				result := make(chan error, 1)
				go func() {
					_, err := p.expect("ack", "mixed")
					result <- err
				}()
				select {
				case err := <-result:
					if err == nil {
						t.Fatalf("invalid control frame was swallowed")
					}
					if p.controlPongs != 0 {
						t.Fatalf("invalid control ping received pong")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("invalid control regression deadlocked")
				}
			})
		}
	})
}
