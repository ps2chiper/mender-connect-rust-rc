// Independent live peer using the upstream Go schemas and private fixture files.
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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

type result struct {
	Passed []string `json:"passed"`
	Error  string   `json:"error,omitempty"`
}
type peer struct {
	c              *websocket.Conn
	proto          ws.ProtoType
	cid            string
	activeShellSID string
	shellDrained   int
	controlPings   int
	controlPongs   int
}

func (p *peer) send(typ, sid string, body []byte, offset *int64) error {
	props := map[string]interface{}{}
	if p.cid != "" {
		props[pf.PropertyConnectionID] = p.cid
	}
	if offset != nil {
		props["offset"] = *offset
	}
	data, err := msgpack.Marshal(ws.ProtoMsg{Header: ws.ProtoHdr{Proto: p.proto, MsgType: typ, SessionID: sid, Properties: props}, Body: body})
	if err != nil {
		return err
	}
	p.c.SetWriteDeadline(time.Now().Add(4 * time.Second))
	return p.c.WriteMessage(websocket.BinaryMessage, data)
}
func (p *peer) request(typ, sid string, body interface{}) error {
	data, err := msgpack.Marshal(body)
	if err != nil {
		return err
	}
	return p.send(typ, sid, data, nil)
}
func (p *peer) next() (ws.ProtoMsg, error) {
	return p.readUntil(time.Now().Add(8 * time.Second))
}

// readUntil returns the next frame before the absolute deadline. It preserves
// the single shared deadline while answering a bounded number of generic
// control pings so that heartbeats cannot mask an expected protocol frame.
func (p *peer) readUntil(deadline time.Time) (ws.ProtoMsg, error) {
	const maxInterleavedPings = 64
	p.c.SetReadLimit(8192)
	for pings := 0; pings <= maxInterleavedPings; pings++ {
		if err := p.c.SetReadDeadline(deadline); err != nil {
			return ws.ProtoMsg{}, err
		}
		_, data, err := p.c.ReadMessage()
		if err != nil {
			return ws.ProtoMsg{}, err
		}
		var m ws.ProtoMsg
		if err = msgpack.Unmarshal(data, &m); err != nil {
			return m, err
		}
		if m.Header.Proto != ws.ProtoTypeControl || m.Header.MsgType != "ping" {
			return m, nil
		}
		if pings == maxInterleavedPings {
			break
		}
		if len(m.Header.SessionID) > 128 {
			return ws.ProtoMsg{}, fmt.Errorf("control ping session id exceeds 128 bytes")
		}
		if len(m.Body) != 0 {
			return ws.ProtoMsg{}, fmt.Errorf("control ping before expected frame carried a body")
		}
		p.controlPings++
		if err = p.sendControlPong(m.Header.SessionID); err != nil {
			return ws.ProtoMsg{}, err
		}
	}
	return ws.ProtoMsg{}, fmt.Errorf("too many interleaved control pings before expected frame")
}

func (p *peer) sendControlPong(sid string) error {
	data, err := msgpack.Marshal(ws.ProtoMsg{Header: ws.ProtoHdr{Proto: ws.ProtoTypeControl, MsgType: "pong", SessionID: sid}})
	if err != nil {
		return err
	}
	p.c.SetWriteDeadline(time.Now().Add(4 * time.Second))
	if err = p.c.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return err
	}
	p.controlPongs++
	return nil
}

func (p *peer) expect(typ, sid string) (ws.ProtoMsg, error) {
	deadline := time.Now().Add(8 * time.Second)
	for drained := 0; drained <= 64; drained++ {
		m, err := p.readUntil(deadline)
		if err != nil {
			return m, err
		}
		if m.Header.Proto == p.proto && m.Header.MsgType == typ && m.Header.SessionID == sid {
			return m, nil
		}
		if os.Getenv("SOAK_DISABLE_DEMUX") != "1" && p.activeShellSID != "" &&
			m.Header.Proto == ws.ProtoTypeShell && m.Header.MsgType == "shell" &&
			m.Header.SessionID == p.activeShellSID && shellStatusOK(m.Header.Properties["status"]) {
			p.shellDrained++
			continue
		}
		return m, fmt.Errorf("expected proto%d %s sid%s; unexpected reply %+v body=%q", p.proto, typ, sid, m.Header, m.Body)
	}
	return ws.ProtoMsg{}, fmt.Errorf("too many interleaved shell frames before %s/%s", typ, sid)
}

func shellStatusOK(value interface{}) bool {
	switch n := value.(type) {
	case int:
		return n == 1
	case int8:
		return n == 1
	case int16:
		return n == 1
	case int32:
		return n == 1
	case int64:
		return n == 1
	case uint:
		return n == 1
	case uint8:
		return n == 1
	case uint16:
		return n == 1
	case uint32:
		return n == 1
	case uint64:
		return n == 1
	default:
		return false
	}
}

func (p *peer) expectError(typ, sid string) error {
	m, err := p.expect("error", sid)
	if err != nil {
		return err
	}
	var e ft.Error
	if err = msgpack.Unmarshal(m.Body, &e); err != nil {
		return err
	}
	if e.Error == nil || *e.Error == "" || e.MessageType == nil || *e.MessageType != typ {
		return fmt.Errorf("invalid upstream transfer error: %+v", e)
	}
	return nil
}
func offset(m ws.ProtoMsg) (int64, error) {
	n, ok := m.Header.Properties["offset"].(int64)
	if !ok {
		return 0, fmt.Errorf("offset must decode as Go int64, got %T", m.Header.Properties["offset"])
	}
	return n, nil
}
func (p *peer) ack(sid string, want int64) error {
	m, err := p.expect("ack", sid)
	if err != nil {
		return err
	}
	if p.proto == ws.ProtoTypeFileTransferV2 {
		// The reference final v2 ACK copies the put_file header, not a chunk
		// header; a request without offset therefore has no ACK offset.
		if len(m.Body) != 0 || len(m.Header.Properties) != 0 {
			return fmt.Errorf("unexpected v2 final ACK body/properties")
		}
		return nil
	}
	n, err := offset(m)
	if err != nil {
		return err
	}
	if n != want || len(m.Body) != 0 {
		return fmt.Errorf("ack offset/body mismatch got%d want%d", n, want)
	}
	return nil
}
func (p *peer) handshake(disabled bool) error {
	saved := p.proto
	p.proto = ws.ProtoTypeControl
	if err := p.request("open", "handshake", ws.Open{Versions: []int{1}}); err != nil {
		return err
	}
	m, err := p.expect("accept", "handshake")
	p.proto = saved
	if err != nil {
		return err
	}
	var a ws.Accept
	if err = msgpack.Unmarshal(m.Body, &a); err != nil {
		return err
	}
	v1, v2 := false, false
	for _, x := range a.Protocols {
		v1 = v1 || x == ws.ProtoTypeFileTransfer
		v2 = v2 || x == ws.ProtoTypeFileTransferV2
	}
	if disabled && (v1 || v2) || !disabled && (!v1 || !v2) {
		return fmt.Errorf("file capability mismatch %v", a.Protocols)
	}
	return nil
}
func (p *peer) download(path, sid string, want []byte) error {
	if err := p.request("get_file", sid, ft.GetFile{Path: &path}); err != nil {
		return err
	}
	got := []byte{}
	for {
		m, err := p.expect("file_chunk", sid)
		if err != nil {
			return err
		}
		n, err := offset(m)
		if err != nil {
			return err
		}
		if n != int64(len(got)) {
			return fmt.Errorf("download noncontiguous offset%d expected%d", n, len(got))
		}
		if len(m.Body) > 4096 {
			return fmt.Errorf("chunk too large")
		}
		got = append(got, m.Body...)
		// Empty-file EOF needs no ACK in the reference handler: offset is
		// already zero and the worker returns immediately after sending EOF.
		if p.proto == ws.ProtoTypeFileTransfer && !(len(m.Body) == 0 && len(got) == 0) {
			if err = p.send("ack", sid, nil, &n); err != nil {
				return err
			}
		}
		if len(m.Body) == 0 {
			break
		}
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("download bytes differ got%d want%d", len(got), len(want))
	}
	return nil
}
func (p *peer) upload(path, sid string, data []byte) error {
	old := []byte("old-visible-destination")
	if err := os.WriteFile(path, old, 0600); err != nil {
		return err
	}
	size := int64(len(data))
	mode := uint32(0640)
	if err := p.request("put_file", sid, ft.UploadRequest{Path: &path, Size: &size, Mode: &mode}); err != nil {
		return err
	}
	if p.proto == ws.ProtoTypeFileTransfer {
		if err := p.ack(sid, 0); err != nil {
			return err
		}
	}
	for start := 0; start < len(data); {
		end := start + 4096
		if end > len(data) {
			end = len(data)
		}
		n := int64(start)
		if err := p.send("file_chunk", sid, data[start:end], &n); err != nil {
			return err
		}
		if p.proto == ws.ProtoTypeFileTransfer {
			if err := p.ack(sid, n); err != nil {
				return err
			}
		}
		start = end
	}
	got, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, old) {
		return fmt.Errorf("destination changed before EOF")
	}
	n := size
	if err = p.send("file_chunk", sid, nil, &n); err != nil {
		return err
	}
	if err = p.ack(sid, size); err != nil {
		return err
	}
	got, err = os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, data) {
		return fmt.Errorf("committed bytes differ")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0640 {
		return fmt.Errorf("committed mode %v", info.Mode())
	}
	return nil
}
func run(c *websocket.Conn, dir, scenario string) ([]string, error) {
	if scenario == "soak" {
		return runSoak(c, dir)
	}
	if strings.HasPrefix(scenario, "mender-") {
		return menderPeer(c, dir, scenario)
	}
	p := &peer{c: c, proto: ws.ProtoTypeFileTransfer}
	if strings.Contains(scenario, "v2") {
		p.proto = ws.ProtoTypeFileTransferV2
	}
	if err := p.handshake(scenario == "disabled"); err != nil {
		return nil, err
	}
	assets := filepath.Join(dir, "assets")
	if err := os.Mkdir(assets, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(assets, "fixture.bin")
	payload := bytes.Repeat([]byte{0, 255, 128, 42, 1, 0, 7}, 23000)
	if scenario == "disabled" {
		if err := p.request("stat", "off", ft.StatFile{Path: &path}); err != nil {
			return nil, err
		}
		if err := p.expectError("stat", "off"); err != nil {
			return nil, err
		}
		return []string{"disabled file transfer omitted and rejected"}, nil
	}
	if err := os.WriteFile(path, payload, 0640); err != nil {
		return nil, err
	}
	switch {
	case scenario == "mixed-close":
		return mixedClose(p, assets, path)
	case scenario == "mixed-progress":
		return mixedProgress(p, assets, path)
	case scenario == "upload-errors":
		return uploadErrors(p, assets, path)
	case strings.HasPrefix(scenario, "header-"):
		return rejectHeader(p, scenario)
	case scenario == "stat":
		stamp := time.Unix(1700000000, 123456789)
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			return nil, err
		}
		if err := p.request("stat", "stat", ft.StatFile{Path: &path}); err != nil {
			return nil, err
		}
		m, err := p.expect("file_info", "stat")
		if err != nil {
			return nil, err
		}
		var info ft.FileInfo
		if err = msgpack.Unmarshal(m.Body, &info); err != nil {
			return nil, err
		}
		if info.Path == nil || *info.Path != path || info.Size == nil || *info.Size != int64(len(payload)) || info.Mode == nil || os.FileMode(*info.Mode) != 0640 || info.ModTime == nil || !info.ModTime.Equal(stamp) {
			return nil, fmt.Errorf("invalid file_info %+v", info)
		}
		if err = p.request("stat", "directory", ft.StatFile{Path: &assets}); err != nil {
			return nil, err
		}
		m, err = p.expect("file_info", "directory")
		if err != nil {
			return nil, err
		}
		if err = msgpack.Unmarshal(m.Body, &info); err != nil {
			return nil, err
		}
		if info.Mode == nil || os.FileMode(*info.Mode)&os.ModeDir == 0 {
			return nil, fmt.Errorf("directory Go mode missing")
		}
		return []string{"upstream file_info exact size/path/mode", "nanosecond MessagePack timestamp decoded by Go", "directory mode preserved"}, nil
	case strings.HasPrefix(scenario, "download-"):
		if err := p.download(path, "same", payload); err != nil {
			return nil, err
		}
		empty := filepath.Join(assets, "empty")
		if err := os.WriteFile(empty, nil, 0600); err != nil {
			return nil, err
		}
		if err := p.download(empty, "same", nil); err != nil {
			return nil, err
		}
		saved := p.proto
		p.proto = ws.ProtoTypeControl
		if err := p.send("ping", "post-download-barrier", nil, nil); err != nil {
			return nil, err
		}
		if _, err := p.expect("pong", "post-download-barrier"); err != nil {
			return nil, err
		}
		p.proto = saved
		return []string{"binary download exceeds v1 window with exact int64 offsets", "EOF and immediate same-session reuse", "empty file transfer"}, nil
	case strings.HasPrefix(scenario, "upload-"):
		if err := p.upload(path, "same", payload); err != nil {
			return nil, err
		}
		if err := p.upload(path, "same", nil); err != nil {
			return nil, err
		}
		return []string{"binary atomic upload with upstream acknowledgement semantics", "old destination unchanged until EOF", "exact bytes and permissions after final ACK", "empty upload and immediate same-session reuse"}, nil
	case scenario == "errors":
		for _, bad := range []string{"", path + "missing", "bad\x00path"} {
			if err := p.request("get_file", "bad", ft.GetFile{Path: &bad}); err != nil {
				return nil, err
			}
			if err := p.expectError("get_file", "bad"); err != nil {
				return nil, err
			}
		}
		negative := int64(-1)
		if err := p.request("put_file", "bad", ft.UploadRequest{Path: &path, Size: &negative}); err != nil {
			return nil, err
		}
		if err := p.expectError("put_file", "bad"); err != nil {
			return nil, err
		}
		link := filepath.Join(assets, "symlink")
		if err := os.Symlink(path, link); err != nil {
			return nil, err
		}
		if err := p.request("get_file", "link", ft.GetFile{Path: &link}); err != nil {
			return nil, err
		}
		if err := p.expectError("get_file", "link"); err != nil {
			return nil, err
		}
		if err := p.download(path, "good", payload); err != nil {
			return nil, err
		}
		return []string{"missing/empty/NUL paths and negative sizes rejected", "symlink download rejected", "valid transfer survives malformed requests"}, nil
	case scenario == "abort" || scenario == "disconnect":
		old := []byte("unchanged")
		if err := os.WriteFile(path, old, 0600); err != nil {
			return nil, err
		}
		size := int64(4096)
		if err := p.request("put_file", "abort", ft.UploadRequest{Path: &path, Size: &size}); err != nil {
			return nil, err
		}
		if err := p.ack("abort", 0); err != nil {
			return nil, err
		}
		n := int64(0)
		if err := p.send("file_chunk", "abort", []byte("partial"), &n); err != nil {
			return nil, err
		}
		if err := p.ack("abort", 0); err != nil {
			return nil, err
		}
		if scenario == "disconnect" {
			c.Close()
		} else {
			if err := p.request("error", "abort", ft.Error{}); err != nil {
				return nil, err
			}
		}
		end := time.Now().Add(3 * time.Second)
		for {
			items, err := os.ReadDir(assets)
			if err != nil {
				return nil, err
			}
			if len(items) == 1 {
				break
			}
			if time.Now().After(end) {
				return nil, fmt.Errorf("staging file survived cancellation: %v", items)
			}
			time.Sleep(20 * time.Millisecond)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(got, old) {
			return nil, fmt.Errorf("aborted upload replaced destination")
		}
		return []string{"precommit cancellation removes temporary file", "old destination preserved"}, nil
	}
	return nil, fmt.Errorf("unknown scenario %s", scenario)
}
func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: file-peer RESULT_DIR SCENARIO")
		os.Exit(2)
	}
	dir, scenario := os.Args[1], os.Args[2]
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.WriteFile(filepath.Join(dir, "endpoint.txt"), []byte(soakScheme()+listener.Addr().String()), 0600)
	completed := make(chan result, 1)
	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	var served atomic.Bool
	mux.HandleFunc("/api/devices/v1/deviceconnect/connect", func(w http.ResponseWriter, r *http.Request) {
		if served.Swap(true) {
			http.Error(w, "fixture already running", 503)
			return
		}
		if r.Header.Get("Authorization") != "Bearer trial-local-token" {
			http.Error(w, "bad auth", 401)
			completed <- result{Error: "incorrect Bearer credential"}
			return
		}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			completed <- result{Error: err.Error()}
			return
		}
		defer c.Close()
		passed, err := run(c, dir, scenario)
		out := result{Passed: passed}
		if err != nil {
			out.Error = err.Error()
		}
		completed <- out
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 4 * time.Second}
	go func() {
		if cert := os.Getenv("SOAK_TLS_CERT"); cert != "" {
			server.ServeTLS(listener, cert, os.Getenv("SOAK_TLS_KEY"))
		} else {
			server.Serve(listener)
		}
	}()
	defer server.Close()
	var out result
	select {
	case out = <-completed:
	case <-time.After(time.Duration(soakSeconds()+60) * time.Second):
		out.Error = "independent file peer timed out"
	}
	data, _ := json.MarshalIndent(out, "", "  ")
	os.WriteFile(filepath.Join(dir, "result.json"), data, 0600)
	fmt.Println(string(data))
	if out.Error != "" {
		os.Exit(1)
	}
}
