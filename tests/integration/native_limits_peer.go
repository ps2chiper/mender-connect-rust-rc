// Independent native file-transfer limits and counter-persistence peer.
//
// TEST HARNESS ONLY. Binds loopback only, speaks the upstream ws/filetransfer
// MessagePack schemas, serializes writes, bounds reads and reports fixed
// behavioural summaries without headers, payloads or environment contents.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	ws "github.com/mendersoftware/go-lib-micro/ws"
	ft "github.com/mendersoftware/go-lib-micro/ws/filetransfer"
	"github.com/vmihailenco/msgpack/v5"
)

const (
	maxReadLimit   = 8192
	maxTotalBytes  = 1 << 20
	readQueueDepth = 128
	peerWriteWait  = 2 * time.Second
	perActionWait  = 5 * time.Second
	overallBudget  = 40 * time.Second
	fileTransferV2 = ws.ProtoType(0x102)
	fixtureSize    = 4096
)

var errBudget = fmt.Errorf("scenario deadline exceeded")

type result struct {
	Ok          bool               `json:"ok"`
	Endpoint    string             `json:"endpoint_path"`
	QemuUsed    bool               `json:"qemu_used"`
	Checks      map[string]bool    `json:"checks"`
	FrameCounts map[string]int     `json:"frame_counts"`
	Durations   map[string]float64 `json:"durations_seconds"`
	Errors      []string           `json:"errors"`
}

type app struct {
	wsPath       string
	token        string
	workdir      string
	endpointFile string
	outputFile   string

	mu        sync.Mutex
	connCount int
	startedAt time.Time
	firstData time.Time
	done      chan struct{}
	doneOnce  sync.Once
	res       *result
}

type peer struct {
	conn   *websocket.Conn
	frames chan *ws.ProtoMsg

	writeMu sync.Mutex
	mu      sync.Mutex
	total   int
	recvErr error
	counts  map[string]int
}

type transferError struct {
	Err     string `msgpack:"err"`
	MsgType string `msgpack:"msgtype,omitempty"`
	MsgID   string `msgpack:"msgid,omitempty"`
}

func main() {
	wsPath := flag.String("ws-path", "/api/devices/v1/deviceconnect/connect", "exact device-connect WebSocket path")
	token := flag.String("token", "", "static dummy bearer token")
	workdir := flag.String("workdir", "", "owned work directory")
	endpointFile := flag.String("endpoint-file", "", "loopback endpoint output")
	outputFile := flag.String("output", "", "JSON result output")
	flag.Parse()

	res := &result{
		Endpoint:    *wsPath,
		QemuUsed:    false,
		Checks:      map[string]bool{},
		FrameCounts: map[string]int{},
		Durations:   map[string]float64{},
		Errors:      []string{},
	}
	a := &app{
		wsPath:       *wsPath,
		token:        *token,
		workdir:      *workdir,
		endpointFile: *endpointFile,
		outputFile:   *outputFile,
		startedAt:    time.Now(),
		done:         make(chan struct{}),
		res:          res,
	}
	if err := a.run(); err != nil {
		res.Ok = false
		res.Errors = append(res.Errors, err.Error())
	}
	a.writeResult()
	if res.Ok {
		os.Exit(0)
	}
	os.Exit(1)
}

func (a *app) run() error {
	if a.endpointFile == "" || a.outputFile == "" || a.workdir == "" || a.token == "" {
		return fmt.Errorf("missing required flags")
	}
	fixture := filepath.Join(a.workdir, "download.bin")
	if err := os.WriteFile(fixture, make([]byte, fixtureSize), 0o600); err != nil {
		return fmt.Errorf("write fixture")
	}
	if err := os.Chmod(fixture, 0o600); err != nil {
		return fmt.Errorf("chmod fixture")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen loopback")
	}
	defer ln.Close()
	if err := writePrivate(a.endpointFile, "http://"+ln.Addr().String()); err != nil {
		return fmt.Errorf("write endpoint")
	}

	srv := &http.Server{Handler: http.HandlerFunc(a.handler), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	select {
	case <-a.done:
		_ = srv.Close()
		return nil
	case <-time.After(overallBudget):
		_ = srv.Close()
		return fmt.Errorf("overall budget exceeded")
	}
}

func (a *app) handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != a.wsPath {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+a.token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	a.mu.Lock()
	a.connCount++
	index := a.connCount
	a.mu.Unlock()
	if index > 2 {
		w.WriteHeader(http.StatusConflict)
		return
	}

	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	conn, err := up.Upgrade(w, r, nil)
	if err != nil {
		a.res.Errors = append(a.res.Errors, "websocket upgrade failed")
		a.res.Ok = false
		a.doneOnce.Do(func() { close(a.done) })
		return
	}
	conn.SetReadLimit(maxReadLimit)
	_ = conn.SetReadDeadline(time.Now().Add(overallBudget))

	d := time.Now().Add(overallBudget)
	if index == 1 {
		a.firstScenario(conn, d)
	} else {
		a.secondScenario(conn, d)
	}
	_ = conn.Close()
	if index == 2 {
		a.doneOnce.Do(func() { close(a.done) })
	}
}

func (a *app) check(name string, ok bool) {
	a.res.Checks[name] = ok
	if !ok {
		a.res.Ok = false
	}
}

func (a *app) setFirstData(now time.Time) {
	a.mu.Lock()
	if a.firstData.IsZero() {
		a.firstData = now
	}
	a.mu.Unlock()
}

func (a *app) firstScenario(conn *websocket.Conn, deadline time.Time) {
	a.res.Ok = true
	p := newPeer(conn, a.res.FrameCounts)
	go p.readLoop()
	fixture := filepath.Join(a.workdir, "download.bin")

	if _, err := p.controlOpen(perAction(deadline), "limits-live"); err != nil {
		a.check("control_open", false)
		return
	}
	a.check("control_open", true)

	// A successful enabled stat is a concise positive file-transfer check.
	path := fixture
	if err := p.ftRequest("limits-stat", "stat", ft.StatFile{Path: &path}); err != nil {
		a.check("enabled_stat", false)
		return
	}
	statOK := false
	_ = p.pump(perAction(deadline), func(m *ws.ProtoMsg) bool {
		if m.Header.Proto != fileTransferV2 || m.Header.SessionID != "limits-stat" {
			return false
		}
		switch m.Header.MsgType {
		case "file_info":
			var info ft.FileInfo
			statOK = decodeBody(m.Body, &info) == nil && info.Size != nil && *info.Size == fixtureSize
			return true
		case "error":
			return true
		}
		return false
	})
	a.check("enabled_stat", statOK)

	// First v2 download must complete before the first five-second EMA tick.
	start := time.Now()
	if err := p.ftRequest("limits-dl-1", "get_file", map[string]interface{}{"path": fixture}); err != nil {
		a.check("first_download_complete", false)
		return
	}
	received := 0
	sawError := false
	err := p.pump(perAction(deadline), func(m *ws.ProtoMsg) bool {
		if m.Header.Proto != fileTransferV2 || m.Header.SessionID != "limits-dl-1" {
			return false
		}
		switch m.Header.MsgType {
		case "file_chunk":
			p.count("first_chunk")
			a.setFirstData(time.Now())
			if len(m.Body) > fixtureSize-received {
				sawError = true
				return true
			}
			received += len(m.Body)
			return received >= fixtureSize
		case "error":
			sawError = true
			return true
		}
		return false
	})
	elapsed := time.Since(start)
	a.res.Durations["first_download"] = elapsed.Seconds()
	a.check("first_download_complete", err == nil && !sawError && received == fixtureSize)
	a.check("first_download_before_ema_tick", elapsed < 5*time.Second)
}

func (a *app) secondScenario(conn *websocket.Conn, deadline time.Time) {
	p := newPeer(conn, a.res.FrameCounts)
	go p.readLoop()

	if _, err := p.controlOpen(perAction(deadline), "limits-live-2"); err != nil {
		a.check("reconnect_control_open", false)
		return
	}
	a.check("reconnect_control_open", true)

	a.mu.Lock()
	first := a.firstData
	a.mu.Unlock()
	if first.IsZero() {
		a.check("rate_error_after_reconnect", false)
		return
	}
	wait := time.Until(first.Add(6 * time.Second))
	if wait > 0 {
		if wait > time.Until(deadline) {
			a.check("rate_error_after_reconnect", false)
			return
		}
		time.Sleep(wait)
	}

	fixture := filepath.Join(a.workdir, "download.bin")
	if err := p.ftRequest("limits-dl-2", "get_file", map[string]interface{}{"path": fixture}); err != nil {
		a.check("rate_error_after_reconnect", false)
		return
	}
	sawError := false
	sawData := false
	structured := false
	err := p.pump(perAction(deadline), func(m *ws.ProtoMsg) bool {
		if m.Header.Proto != fileTransferV2 || m.Header.SessionID != "limits-dl-2" {
			return false
		}
		switch m.Header.MsgType {
		case "error":
			sawError = true
			var te transferError
			structured = decodeBody(m.Body, &te) == nil && te.Err == "transfer rate limit exceeded" && te.MsgType == "get_file"
			return true
		case "file_chunk":
			sawData = true
			return true
		}
		return false
	})
	a.check("rate_error_after_reconnect", err == nil && sawError && structured && !sawData)
	a.check("rate_error_before_data", !sawData)
}

func newPeer(conn *websocket.Conn, counts map[string]int) *peer {
	return &peer{
		conn:   conn,
		frames: make(chan *ws.ProtoMsg, readQueueDepth),
		counts: counts,
	}
}

func (p *peer) readLoop() {
	defer close(p.frames)
	for {
		_, data, err := p.conn.ReadMessage()
		if err != nil {
			p.setErr(fmt.Errorf("connection read failed"))
			return
		}
		p.mu.Lock()
		p.total += len(data)
		over := p.total > maxTotalBytes
		p.mu.Unlock()
		if over {
			p.setErr(fmt.Errorf("collected bytes exceeded bound"))
			return
		}
		var m ws.ProtoMsg
		if err := msgpack.Unmarshal(data, &m); err != nil {
			p.setErr(fmt.Errorf("decode protocol message"))
			return
		}
		select {
		case p.frames <- &m:
		default:
			p.setErr(fmt.Errorf("reader queue overflow"))
			return
		}
	}
}

func (p *peer) setErr(err error) {
	p.mu.Lock()
	if p.recvErr == nil {
		p.recvErr = err
	}
	p.mu.Unlock()
}

func (p *peer) count(key string) {
	p.writeMu.Lock()
	p.counts[key]++
	p.writeMu.Unlock()
}

func (p *peer) send(m *ws.ProtoMsg) error {
	data, err := msgpack.Marshal(m)
	if err != nil {
		return err
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	_ = p.conn.SetWriteDeadline(time.Now().Add(peerWriteWait))
	return p.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (p *peer) pump(deadline time.Time, handle func(*ws.ProtoMsg) bool) error {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	for {
		select {
		case m, ok := <-p.frames:
			if !ok {
				return fmt.Errorf("connection closed")
			}
			if m.Header.MsgType == "ping" {
				p.autoPong(m)
				continue
			}
			if handle(m) {
				return nil
			}
		case <-timer.C:
			return errBudget
		}
	}
}

func (p *peer) autoPong(m *ws.ProtoMsg) {
	if m.Header.Proto != ws.ProtoTypeControl {
		return
	}
	p.count("control_ping_received")
	_ = p.send(&ws.ProtoMsg{Header: ws.ProtoHdr{
		Proto:     ws.ProtoTypeControl,
		MsgType:   "pong",
		SessionID: m.Header.SessionID,
	}})
}

func (p *peer) controlOpen(deadline time.Time, sid string) (*ws.Accept, error) {
	body, err := msgpack.Marshal(ws.Open{Versions: []int{1}})
	if err != nil {
		return nil, err
	}
	if err := p.send(&ws.ProtoMsg{Header: ws.ProtoHdr{Proto: ws.ProtoTypeControl, MsgType: "open", SessionID: sid}, Body: body}); err != nil {
		return nil, err
	}
	var out *ws.Accept
	err = p.pump(deadline, func(m *ws.ProtoMsg) bool {
		if m.Header.Proto == ws.ProtoTypeControl && m.Header.MsgType == "accept" && m.Header.SessionID == sid {
			var accept ws.Accept
			if msgpack.Unmarshal(m.Body, &accept) == nil {
				out = &accept
				return true
			}
		}
		return false
	})
	return out, err
}

func (p *peer) ftRequest(sid, typ string, body interface{}) error {
	data, err := msgpack.Marshal(body)
	if err != nil {
		return err
	}
	return p.send(&ws.ProtoMsg{Header: ws.ProtoHdr{Proto: fileTransferV2, MsgType: typ, SessionID: sid}, Body: data})
}

func perAction(deadline time.Time) time.Time {
	d := time.Now().Add(perActionWait)
	if d.After(deadline) {
		return deadline
	}
	return d
}

func decodeBody(body []byte, v interface{}) error {
	if len(body) == 0 {
		return fmt.Errorf("empty body")
	}
	return msgpack.Unmarshal(body, v)
}

func writePrivate(path, data string) error {
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func (a *app) writeResult() {
	if a.res.Checks == nil {
		a.res.Checks = map[string]bool{}
	}
	if a.res.FrameCounts == nil {
		a.res.FrameCounts = map[string]int{}
	}
	if a.res.Durations == nil {
		a.res.Durations = map[string]float64{}
	}
	if a.outputFile == "" {
		return
	}
	data, err := json.MarshalIndent(a.res, "", "  ")
	if err != nil {
		return
	}
	_ = writePrivate(a.outputFile, string(data))
}
