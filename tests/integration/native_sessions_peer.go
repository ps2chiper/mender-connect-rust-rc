// Independent native protocol peer for the mender-connect Rust trial.
//
// TEST HARNESS ONLY. This program is a loopback WebSocket peer that emulates
// the device-connect server side of the Mender protocol. It speaks the real
// upstream ws/shell/control MessagePack schemas (go-lib-micro/ws) over a
// gorilla/websocket connection and drives a bounded set of protocol scenarios
// against a frozen candidate daemon.
//
// Guarantees enforced here:
//   - binds 127.0.0.1:0 only;
//   - accepts exactly one connection on the configured device-connect path with
//     a static, dummy bearer token;
//   - never logs request headers, tokens, message bodies or payloads;
//   - bounds read frame size and total collected bytes;
//   - serialises all writes and uses a single bounded reader queue;
//   - owns an explicit overall deadline and reports unexpected protocol
//     behaviour as a failure via the JSON result.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	ws "github.com/mendersoftware/go-lib-micro/ws"
	ft "github.com/mendersoftware/go-lib-micro/ws/filetransfer"
	"github.com/mendersoftware/go-lib-micro/ws/shell"
	"github.com/vmihailenco/msgpack/v5"
)

const (
	maxReadLimit    = 8192
	maxTotalBytes   = 1 << 20
	maxBodyBytes    = 64 * 1024
	readQueueDepth  = 256
	peerWriteWait   = 2 * time.Second
	perActionWait   = 5 * time.Second
	genericLongWait = 70 * time.Second
	overallBudget   = 95 * time.Second
)

var errBudget = fmt.Errorf("scenario deadline exceeded")

// result mirrors the fields the controller merges into its signed-off report.
type result struct {
	Ok               bool               `json:"ok"`
	EndpointPath     string             `json:"endpoint_path"`
	NativeArch       string             `json:"native_arch"`
	QemuUsed         bool               `json:"qemu_used"`
	Checks           map[string]bool    `json:"checks"`
	FrameCounts      map[string]int     `json:"frame_counts"`
	Durations        map[string]float64 `json:"durations_seconds"`
	Sessions         map[string]string  `json:"sessions"`
	ControlVersion   int                `json:"control_version"`
	ControlProtocols []int              `json:"control_protocols"`
	Errors           []string           `json:"errors"`
}

type app struct {
	wsPath       string
	token        string
	workdir      string
	endpointFile string
	outputFile   string

	mu        sync.Mutex
	connected bool
	done      chan struct{}
	res       *result
}

type peer struct {
	conn   *websocket.Conn
	frames chan *ws.ProtoMsg

	writeMu sync.Mutex
	mu      sync.Mutex
	total   int
	recvErr error

	counts   map[string]int
	skipPong map[string]bool

	start time.Time

	metaMu          sync.Mutex
	genericPingAt   map[string]time.Duration
	controlPingSids map[string]bool
	controlOpenTime map[string]time.Time
	idleClosedAt    time.Duration
}

// Control protocol error body schema (MessagePack, matching the Rust protocol).
type ctrlError struct {
	Error        string       `msgpack:"err"`
	Close        bool         `msgpack:"close"`
	Code         int          `msgpack:"code,omitempty"`
	MessageProto ws.ProtoType `msgpack:"msgproto,omitempty"`
	MessageType  string       `msgpack:"msgtype,omitempty"`
	MessageId    string       `msgpack:"msgid,omitempty"`
}

func main() {
	wsPath := flag.String("ws-path", "/api/devices/v1/deviceconnect/connect", "exact device-connect WebSocket path to accept")
	token := flag.String("token", "", "static dummy bearer token to require")
	workdir := flag.String("workdir", "", "owned work directory for file-transfer fixtures")
	endpointFile := flag.String("endpoint-file", "", "file to write the loopback endpoint base into")
	outputFile := flag.String("output", "", "JSON result output path")
	flag.Parse()

	res := &result{
		EndpointPath: *wsPath,
		QemuUsed:     false,
		Checks:       map[string]bool{},
		FrameCounts:  map[string]int{},
		Durations:    map[string]float64{},
		Sessions:     map[string]string{},
		Errors:       []string{},
	}
	a := &app{
		wsPath:       *wsPath,
		token:        *token,
		workdir:      *workdir,
		endpointFile: *endpointFile,
		outputFile:   *outputFile,
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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen loopback")
	}
	defer ln.Close()

	base := "http://" + ln.Addr().String()
	if err := writePrivate(a.endpointFile, base); err != nil {
		return fmt.Errorf("write endpoint file")
	}

	srv := &http.Server{Handler: http.HandlerFunc(a.handler), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	select {
	case <-a.done:
		_ = srv.Close()
		return nil
	case <-time.After(overallBudget):
		_ = srv.Close()
		return fmt.Errorf("no daemon connection within budget")
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
	if a.connected {
		a.mu.Unlock()
		w.WriteHeader(http.StatusConflict)
		return
	}
	a.connected = true
	a.mu.Unlock()

	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	conn, err := up.Upgrade(w, r, nil)
	if err != nil {
		a.res.Errors = append(a.res.Errors, "websocket upgrade failed")
		a.res.Ok = false
		close(a.done)
		return
	}
	conn.SetReadLimit(maxReadLimit)
	_ = conn.SetReadDeadline(time.Now().Add(overallBudget))

	a.runScenarios(conn)
	_ = conn.Close()
	close(a.done)
}

func (a *app) runScenarios(conn *websocket.Conn) {
	a.res.Ok = true
	p := &peer{
		conn:            conn,
		frames:          make(chan *ws.ProtoMsg, readQueueDepth),
		counts:          a.res.FrameCounts,
		skipPong:        map[string]bool{},
		start:           time.Now(),
		genericPingAt:   map[string]time.Duration{},
		controlPingSids: map[string]bool{},
		controlOpenTime: map[string]time.Time{},
	}
	go p.readLoop()

	deadline := p.start.Add(overallBudget)
	a.legacyShellScenarios(p, deadline)
	a.fileScenarios(p, deadline)
	a.legacyMarkerAfterFiles(p, deadline)
	a.controlScenarios(p, deadline)
	a.postTimeoutScenarios(p, deadline)

	p.writeMu.Lock()
	shellPings := p.counts["shell_ping_received"]
	shellPongs := p.counts["shell_pong_sent"]
	p.writeMu.Unlock()
	a.check("legacy_shell_ping_positive", shellPings > 0)
	a.check("legacy_shell_pong_positive", shellPongs > 0)

	_ = conn.Close()
	// Join the reader goroutine before the result is serialised so there is no
	// data race on shared state. A read error after our own intentional close is
	// expected and must not be reported as a failure; genuine mid-run read
	// failures surface earlier as a pump error.
	joined := false
	joinDeadline := time.Now().Add(2 * time.Second)
drain:
	for {
		select {
		case _, ok := <-p.frames:
			if !ok {
				joined = true
				break drain
			}
		case <-time.After(time.Until(joinDeadline)):
			break drain
		}
	}
	a.check("reader_joined", joined)
}

func (a *app) check(name string, ok bool) {
	a.res.Checks[name] = ok
	if !ok {
		a.res.Ok = false
	}
}

// ----- peer plumbing -------------------------------------------------------

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
		m, derr := decodeMsg(data)
		if derr != nil {
			p.setErr(fmt.Errorf("decode protocol message: %v", derr))
			return
		}
		select {
		case p.frames <- m:
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

func (p *peer) recvFailed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.recvErr != nil
}

func (p *peer) count(key string) {
	p.writeMu.Lock()
	p.counts[key]++
	p.writeMu.Unlock()
}

func (p *peer) send(m *ws.ProtoMsg) error {
	data, err := encodeMsg(m)
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
				p.mu.Lock()
				e := p.recvErr
				p.mu.Unlock()
				if e == nil {
					e = fmt.Errorf("connection closed")
				}
				return e
			}
			if m.Header.MsgType == "ping" {
				p.handlePing(m)
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

func (p *peer) handlePing(m *ws.ProtoMsg) {
	sid := m.Header.SessionID
	switch m.Header.Proto {
	case ws.ProtoTypeShell:
		p.count("shell_ping_received")
		_ = p.send(&ws.ProtoMsg{Header: ws.ProtoHdr{Proto: ws.ProtoTypeShell, MsgType: shell.MessageTypePongShell, SessionID: sid}})
		p.count("shell_pong_sent")
	case ws.ProtoTypeControl:
		p.count("control_ping_received")
		p.recordGenericPing(sid)
		if !p.skipPong[sid] {
			_ = p.send(&ws.ProtoMsg{Header: ws.ProtoHdr{Proto: ws.ProtoTypeControl, MsgType: "pong", SessionID: sid}})
			p.count("control_pong_sent")
		} else {
			p.count("control_ping_unanswered")
		}
	}
}

func (p *peer) recordGenericPing(sid string) {
	p.metaMu.Lock()
	defer p.metaMu.Unlock()
	if _, ok := p.genericPingAt[sid]; !ok {
		base := p.start
		if t, ok := p.controlOpenTime[sid]; ok {
			base = t
		}
		p.genericPingAt[sid] = time.Since(base)
	}
	p.controlPingSids[sid] = true
}

// ----- shell scenarios -----------------------------------------------------

type markerSpec struct {
	command string
	marker  string
}

func splitMarker(tag string) markerSpec {
	// The marker is assembled from two printf parts so that the echoed command
	// text cannot itself contain the success marker.
	marker := "MRK" + tag + "_DONE"
	cmd := fmt.Sprintf("printf '%%s%%s\\n' 'MRK%s_' 'DONE'; stty -echo\n", tag)
	return markerSpec{command: cmd, marker: marker}
}

func shellStatus(m *ws.ProtoMsg) (int, bool) {
	if m.Header.Properties == nil {
		return 0, false
	}
	v, ok := m.Header.Properties["status"]
	if !ok {
		return 0, false
	}
	return statusInt(v)
}

func statusInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return boundedStatus(int64(n))
	case int8:
		return boundedStatus(int64(n))
	case int16:
		return boundedStatus(int64(n))
	case int32:
		return boundedStatus(int64(n))
	case int64:
		return boundedStatus(n)
	case uint:
		return boundedStatus(int64(n))
	case uint8:
		return boundedStatus(int64(n))
	case uint16:
		return boundedStatus(int64(n))
	case uint32:
		return boundedStatus(int64(n))
	case uint64:
		if n > 3 {
			return 0, false
		}
		return int(n), true
	}
	return 0, false
}

func boundedStatus(n int64) (int, bool) {
	if n < 1 || n > 3 {
		return 0, false
	}
	return int(n), true
}

func propInt64(props map[string]interface{}, key string) (int64, bool) {
	if props == nil {
		return 0, false
	}
	v, ok := props[key]
	if !ok {
		return 0, false
	}
	n, ok := v.(int64)
	if !ok {
		return 0, false
	}
	return n, true
}

func perAction(deadline time.Time) time.Time {
	d := time.Now().Add(perActionWait)
	if d.After(deadline) {
		return deadline
	}
	return d
}

func replyStatusIs(m *ws.ProtoMsg, want shell.MenderShellMessageStatus) bool {
	st, ok := shellStatus(m)
	return ok && st == int(want)
}

func (p *peer) shellNew(deadline time.Time, sid, user string) (*ws.ProtoMsg, error) {
	props := map[string]interface{}{"user_id": user}
	if err := p.send(&ws.ProtoMsg{Header: ws.ProtoHdr{Proto: ws.ProtoTypeShell, MsgType: shell.MessageTypeSpawnShell, SessionID: sid, Properties: props}}); err != nil {
		return nil, err
	}
	var out *ws.ProtoMsg
	err := p.pump(deadline, func(m *ws.ProtoMsg) bool {
		if m.Header.Proto == ws.ProtoTypeShell && m.Header.MsgType == shell.MessageTypeSpawnShell && m.Header.SessionID == sid {
			out = m
			return true
		}
		return false
	})
	return out, err
}

func (p *peer) shellCommand(deadline time.Time, sid, command, marker string) error {
	if err := p.send(&ws.ProtoMsg{Header: ws.ProtoHdr{Proto: ws.ProtoTypeShell, MsgType: shell.MessageTypeShellCommand, SessionID: sid}, Body: []byte(command)}); err != nil {
		return err
	}
	var acc bytes.Buffer
	found := false
	err := p.pump(deadline, func(m *ws.ProtoMsg) bool {
		if m.Header.Proto == ws.ProtoTypeShell && m.Header.SessionID == sid && m.Header.MsgType == shell.MessageTypeShellCommand {
			st, ok := shellStatus(m)
			if !ok || st != int(shell.NormalMessage) {
				return false
			}
			if acc.Len()+len(m.Body) > maxBodyBytes {
				return false
			}
			acc.Write(m.Body)
			if bytes.Contains(acc.Bytes(), []byte(marker)) {
				found = true
				return true
			}
		}
		return false
	})
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("marker not observed")
	}
	return nil
}

func (p *peer) shellStop(deadline time.Time, sid, user string) (*ws.ProtoMsg, error) {
	props := map[string]interface{}{}
	if user != "" {
		props["user_id"] = user
	}
	if err := p.send(&ws.ProtoMsg{Header: ws.ProtoHdr{Proto: ws.ProtoTypeShell, MsgType: shell.MessageTypeStopShell, SessionID: sid, Properties: props}}); err != nil {
		return nil, err
	}
	var out *ws.ProtoMsg
	err := p.pump(deadline, func(m *ws.ProtoMsg) bool {
		if m.Header.Proto != ws.ProtoTypeShell {
			return false
		}
		switch m.Header.MsgType {
		case shell.MessageTypeStopShell:
			if m.Header.SessionID == sid {
				out = m
				return true
			}
			// A stop notice for another session is expected; account for it.
			p.count("shell_stop_notice")
		case shell.MessageTypeShellCommand:
			p.count("shell_trailing_output")
		}
		return false
	})
	return out, err
}

func (a *app) legacyShellScenarios(p *peer, deadline time.Time) {
	ra, err := p.shellNew(perAction(deadline), "sid-a", "usera")
	a.check("legacy_new_usera", err == nil && ra != nil && replyStatusIs(ra, shell.NormalMessage))
	rb, err := p.shellNew(perAction(deadline), "sid-b", "userb")
	a.check("legacy_new_userb", err == nil && rb != nil && replyStatusIs(rb, shell.NormalMessage))
	a.res.Sessions["sid-a"] = "usera"
	a.res.Sessions["sid-b"] = "userb"
	a.res.Sessions["sid-c2"] = "userc"

	ma := splitMarker("ALPHA")
	a.check("legacy_marker_a", p.shellCommand(perAction(deadline), "sid-a", ma.command, ma.marker) == nil)

	mb := splitMarker("BRAVO")
	a.check("legacy_marker_b", p.shellCommand(perAction(deadline), "sid-b", mb.command, mb.marker) == nil)

	// A second session for an already-active logical user must be rejected.
	rc, err := p.shellNew(perAction(deadline), "sid-c", "usera")
	a.check("legacy_duplicate_user_rejected", err == nil && rc != nil && replyStatusIs(rc, shell.ErrorMessage))

	// Stopping one session must leave the other responsive.
	stopA, err := p.shellStop(perAction(deadline), "sid-a", "usera")
	a.check("legacy_stop_a_acked", err == nil && stopA != nil && replyStatusIs(stopA, shell.NormalMessage))
	mb2 := splitMarker("CHARLIE")
	a.check("legacy_b_survives_stop_a", p.shellCommand(perAction(deadline), "sid-b", mb2.command, mb2.marker) == nil)

	// Empty-SID stop with an explicit user stops that user's session and acks
	// the empty-SID request.
	rs, err := p.shellStop(perAction(deadline), "", "userb")
	a.check("legacy_stop_empty_sid_userb", err == nil && rs != nil && replyStatusIs(rs, shell.NormalMessage))

	// Empty SID and empty user must produce an error.
	re, err := p.shellStop(perAction(deadline), "", "")
	a.check("legacy_stop_empty_both_error", err == nil && re != nil && replyStatusIs(re, shell.ErrorMessage))

	// A later logical user reuses freed session slots; keep it alive for the
	// post-transfer and post-timeout liveness checks.
	rd, err := p.shellNew(perAction(deadline), "sid-c2", "userc")
	a.check("legacy_user_c_reuses_slot", err == nil && rd != nil && replyStatusIs(rd, shell.NormalMessage))
}

func (a *app) legacyMarkerAfterFiles(p *peer, deadline time.Time) {
	m := splitMarker("ECHO")
	a.check("legacy_alive_after_file_transfer", p.shellCommand(perAction(deadline), "sid-c2", m.command, m.marker) == nil)
}

// ----- control / file scenarios --------------------------------------------

func (p *peer) controlOpen(deadline time.Time, sid string) (*ws.Accept, error) {
	body, err := encodeBody(ws.Open{Versions: []int{1}})
	if err != nil {
		return nil, err
	}
	if err := p.send(&ws.ProtoMsg{Header: ws.ProtoHdr{Proto: ws.ProtoTypeControl, MsgType: "open", SessionID: sid}, Body: body}); err != nil {
		return nil, err
	}
	var out *ws.Accept
	err = p.pump(deadline, func(m *ws.ProtoMsg) bool {
		if m.Header.Proto == ws.ProtoTypeControl && m.Header.MsgType == "accept" && m.Header.SessionID == sid {
			var r ws.Accept
			if decodeBody(m.Body, &r) == nil {
				out = &r
				return true
			}
		}
		return false
	})
	return out, err
}

func protoSet(protocols []ws.ProtoType) map[int]bool {
	set := map[int]bool{}
	for _, pr := range protocols {
		set[int(pr)] = true
	}
	return set
}

func (a *app) controlScenarios(p *peer, deadline time.Time) {
	p.metaMu.Lock()
	p.controlOpenTime["ctrl-live"] = time.Now()
	p.metaMu.Unlock()
	live, err := p.controlOpen(perAction(deadline), "ctrl-live")
	a.check("control_open_live", err == nil && live != nil && live.Version == 1)
	p.metaMu.Lock()
	p.controlOpenTime["ctrl-idle"] = time.Now()
	p.metaMu.Unlock()
	idle, err := p.controlOpen(perAction(deadline), "ctrl-idle")
	a.check("control_open_idle", err == nil && idle != nil && idle.Version == 1)

	if live != nil {
		a.res.ControlVersion = live.Version
		set := protoSet(live.Protocols)
		a.res.ControlProtocols = sortedKeys(set)
		a.check("control_shell_protocol", set[int(ws.ProtoTypeShell)])
		a.check("control_file_v1", set[int(ws.ProtoTypeFileTransfer)])
		a.check("control_file_v2", set[0x102])
		a.check("control_pf_v1", set[3])
		a.check("control_pf_v2", set[0x103])
		a.check("control_no_mender_client", !set[4])
		want := map[int]bool{1: true, 2: true, 258: true, 3: true, 259: true}
		exact := len(set) == len(want)
		for k := range want {
			if !set[k] {
				exact = false
			}
		}
		a.check("control_protocol_set_exact", exact)
	}

	// The idle generic session is deliberately left un-ponged so the daemon's
	// session timer must close it; every other control session is auto-ponged.
	p.skipPong["ctrl-idle"] = true

	waitDeadline := time.Now().Add(genericLongWait)
	if waitDeadline.After(deadline) {
		waitDeadline = deadline
	}
	var idleClosed, liveErrored bool
	err = p.pump(waitDeadline, func(m *ws.ProtoMsg) bool {
		if m.Header.Proto != ws.ProtoTypeControl || m.Header.MsgType != "error" {
			return false
		}
		var e ctrlError
		if decodeBody(m.Body, &e) != nil {
			return false
		}
		switch m.Header.SessionID {
		case "ctrl-idle":
			if e.Close && errorMentionsIdle(e.Error) {
				idleClosed = true
				p.metaMu.Lock()
				base := p.start
				if t, ok := p.controlOpenTime["ctrl-idle"]; ok {
					base = t
				}
				p.idleClosedAt = time.Since(base)
				p.metaMu.Unlock()
				return true
			}
		case "ctrl-live":
			liveErrored = true
		}
		return false
	})
	a.check("control_idle_session_timeout", idleClosed && err == nil)
	a.check("control_live_not_closed", !liveErrored)

	p.metaMu.Lock()
	pingLive, okLive := p.genericPingAt["ctrl-live"]
	pingIdle, okIdle := p.genericPingAt["ctrl-idle"]
	idleAt := p.idleClosedAt
	legacyPinged := false
	for _, ls := range []string{"sid-a", "sid-b", "sid-c2"} {
		if p.controlPingSids[ls] {
			legacyPinged = true
		}
	}
	p.metaMu.Unlock()

	a.res.Durations["control_generic_ping_live"] = pingLive.Seconds()
	a.res.Durations["control_generic_ping_idle"] = pingIdle.Seconds()
	a.res.Durations["control_idle_close"] = idleAt.Seconds()
	a.check("control_generic_ping_live", okLive && pingLive >= 46*time.Second && pingLive <= 55*time.Second)
	a.check("control_generic_ping_idle", okIdle && pingIdle >= 46*time.Second && pingIdle <= 55*time.Second)
	a.check("control_idle_close_timing", idleClosed && idleAt >= 58*time.Second && idleAt <= 65*time.Second)
	a.check("control_no_generic_ping_legacy", !legacyPinged)
}

func errorMentionsIdle(msg string) bool {
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "timeout") || strings.Contains(lower, "idle") || strings.Contains(lower, "expire")
}

func (a *app) postTimeoutScenarios(p *peer, deadline time.Time) {
	// A legacy shell that was never involved in the transfers must still be
	// alive after them and after the generic control idle timeout.
	m := splitMarker("DELTA")
	a.check("legacy_alive_after_timeout", p.shellCommand(perAction(deadline), "sid-c2", m.command, m.marker) == nil)

	// Explicit live CONTROL ping/pong verification after the idle timeout.
	if err := p.send(&ws.ProtoMsg{Header: ws.ProtoHdr{Proto: ws.ProtoTypeControl, MsgType: "ping", SessionID: "ctrl-live"}}); err != nil {
		a.check("control_live_ping_pong", false)
		return
	}
	got := false
	liveErrorSeen := false
	err := p.pump(perAction(deadline), func(m *ws.ProtoMsg) bool {
		if m.Header.Proto == ws.ProtoTypeControl && m.Header.SessionID == "ctrl-live" {
			if m.Header.MsgType == "pong" {
				got = true
				return true
			}
			if m.Header.MsgType == "error" {
				liveErrorSeen = true
				return true
			}
		}
		return false
	})
	a.check("control_live_ping_pong", got && err == nil)
	a.check("control_live_no_late_error", !liveErrorSeen)
}

func sortedKeys(set map[int]bool) []int {
	out := make([]int, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	// insertion sort: tiny slice, keeps deterministic output without importing sort
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

func (p *peer) ftSend(typ, sid string, body []byte, offset *int64) error {
	props := map[string]interface{}{}
	if offset != nil {
		props["offset"] = *offset
	}
	return p.send(&ws.ProtoMsg{Header: ws.ProtoHdr{Proto: ws.ProtoTypeFileTransfer, MsgType: typ, SessionID: sid, Properties: props}, Body: body})
}

func (p *peer) ftRequest(sid, typ string, body interface{}) error {
	data, err := encodeBody(body)
	if err != nil {
		return err
	}
	return p.ftSend(typ, sid, data, nil)
}

func (a *app) fileScenarios(p *peer, deadline time.Time) {
	contents := []byte("hello-file-info")
	existing := filepath.Join(a.workdir, "existing.bin")
	if err := writePrivateBytes(existing, contents); err != nil {
		a.check("file_fixture_existing", false)
		return
	}
	a.check("file_fixture_existing", true)

	// Stat an existing file. The request path travels in the MessagePack body;
	// the header carries no offset.
	if _, err := p.controlOpen(perAction(deadline), "file-stat"); err != nil {
		a.check("file_stat_existing", false)
	} else {
		statPath := existing
		statOK := false
		if err := p.ftRequest("file-stat", "stat", ft.StatFile{Path: &statPath}); err == nil {
			var info ft.FileInfo
			gotInfo := false
			_ = p.pump(perAction(deadline), func(m *ws.ProtoMsg) bool {
				if m.Header.Proto == ws.ProtoTypeFileTransfer && m.Header.SessionID == "file-stat" {
					switch m.Header.MsgType {
					case "file_info":
						if decodeBody(m.Body, &info) == nil {
							gotInfo = true
						}
						return true
					case "error":
						return true
					}
				}
				return false
			})
			statOK = gotInfo &&
				info.Path != nil && *info.Path == existing &&
				info.Size != nil && *info.Size == int64(len(contents)) &&
				info.Mode != nil && os.FileMode(*info.Mode).Perm() == 0o600
		}
		a.check("file_stat_existing", statOK)

		// A stat of a missing path must produce an error frame, not a file_info.
		missing := filepath.Join(a.workdir, "missing.bin")
		sawError := false
		if err := p.ftRequest("file-stat", "stat", ft.StatFile{Path: &missing}); err == nil {
			_ = p.pump(perAction(deadline), func(m *ws.ProtoMsg) bool {
				if m.Header.Proto == ws.ProtoTypeFileTransfer && m.Header.SessionID == "file-stat" {
					switch m.Header.MsgType {
					case "error":
						sawError = true
						return true
					case "file_info":
						return true
					}
				}
				return false
			})
		}
		a.check("file_stat_missing_error", sawError)
	}

	a.emptyUpload(p, deadline)
}

func (a *app) emptyUpload(p *peer, deadline time.Time) {
	target := filepath.Join(a.workdir, "empty-upload.bin")
	_ = os.Remove(target)
	if _, err := p.controlOpen(perAction(deadline), "file-put"); err != nil {
		a.check("file_empty_upload_committed", false)
		return
	}
	path := target
	size := int64(0)
	if err := p.ftRequest("file-put", "put_file", ft.UploadRequest{Path: &path, Size: &size}); err != nil {
		a.check("file_empty_upload_committed", false)
		return
	}
	// Wait for the initial ACK at offset 0 before sending the EOF chunk. The
	// pump can return nil on an error frame, so require the explicit gotAck flag
	// and reject any upload error frame rather than assuming success.
	gotAck := false
	sawUploadError := false
	err := p.pump(perAction(deadline), func(m *ws.ProtoMsg) bool {
		if m.Header.Proto == ws.ProtoTypeFileTransfer && m.Header.SessionID == "file-put" {
			switch m.Header.MsgType {
			case "ack":
				if off, ok := propInt64(m.Header.Properties, "offset"); ok && off == 0 {
					gotAck = true
					return true
				}
				return false
			case "error":
				sawUploadError = true
				return true
			}
		}
		return false
	})
	if err != nil || !gotAck || sawUploadError {
		a.check("file_empty_upload_committed", false)
		return
	}
	// EOF for an empty upload: file_chunk with an explicit int64(0) offset and
	// an empty body, followed immediately by a CONTROL close.
	eofOffset := int64(0)
	if err := p.ftSend("file_chunk", "file-put", nil, &eofOffset); err != nil {
		a.check("file_empty_upload_committed", false)
		return
	}
	closeMsg := &ws.ProtoMsg{Header: ws.ProtoHdr{Proto: ws.ProtoTypeControl, MsgType: "close", SessionID: "file-put"}}
	if err := p.send(closeMsg); err != nil {
		a.check("file_empty_upload_committed", false)
		return
	}

	committed := false
	end := time.Now().Add(perActionWait)
	for time.Now().Before(end) {
		if info, statErr := os.Stat(target); statErr == nil && info.Size() == 0 {
			committed = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	a.check("file_empty_upload_committed", committed)
}

// ----- encode / decode -----------------------------------------------------

func encodeMsg(m *ws.ProtoMsg) ([]byte, error) {
	return msgpack.Marshal(m)
}

func decodeMsg(data []byte) (*ws.ProtoMsg, error) {
	var m ws.ProtoMsg
	if err := msgpack.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func encodeBody(v interface{}) ([]byte, error) {
	return msgpack.Marshal(v)
}

func decodeBody(b []byte, v interface{}) error {
	if len(b) == 0 {
		return fmt.Errorf("empty body")
	}
	return msgpack.Unmarshal(b, v)
}

// ----- file helpers --------------------------------------------------------

func writePrivate(path, data string) error {
	return writePrivateBytes(path, []byte(data))
}

func writePrivateBytes(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
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
	_ = writePrivateBytes(a.outputFile, data)
}
