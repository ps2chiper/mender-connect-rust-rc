package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mendersoftware/go-lib-micro/ws"
	"github.com/vmihailenco/msgpack/v5"
)

const (
	stabSessionID      = "stability"
	stabInitialIdle    = 25 * time.Second
	stabFollowUp       = 15 * time.Second
	stabResponseWindow = 8 * time.Second
	stabResizeWrite    = 4 * time.Second
	stabChanCap        = 16
	stabOutputLimit    = 64 * 1024
	stabCleanupWait    = time.Second
	stabExtraSlack     = 60 * time.Second
)

type stabResp struct {
	m   ws.ProtoMsg
	err error
}

type stabProgress struct {
	ElapsedSeconds int  `json:"elapsed_seconds"`
	Commands       int  `json:"commands"`
	Pings          int  `json:"pings"`
	Pongs          int  `json:"pongs"`
	ControlPings   int  `json:"control_pings"`
	ControlPongs   int  `json:"control_pongs"`
	ResizeVerified bool `json:"resize_verified"`
}

type stabMetrics struct {
	Passed         bool `json:"passed"`
	SoakSeconds    int  `json:"soak_seconds"`
	ElapsedSeconds int  `json:"elapsed_seconds"`
	Commands       int  `json:"commands"`
	Pings          int  `json:"pings"`
	Pongs          int  `json:"pongs"`
	ControlPings   int  `json:"control_pings"`
	ControlPongs   int  `json:"control_pongs"`
	ResizeVerified bool `json:"resize_verified"`
}

type stabStatusBody struct {
	Status int `msgpack:"status"`
}

func stabSoakSeconds() (int, error) {
	raw := os.Getenv("SOAK_SECONDS")
	if raw == "" {
		return 0, fmt.Errorf("SOAK_SECONDS is not set")
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("SOAK_SECONDS is not a number")
	}
	if n < 30 || n > 3600 {
		return 0, fmt.Errorf("SOAK_SECONDS out of supported range")
	}
	return n, nil
}

func stabOctal(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "\\%03o", s[i])
	}
	return b.String()
}

func stabBoundedStatus(n int64) (int, bool) {
	if n < 0 || n > 3 {
		return 0, false
	}
	return int(n), true
}

func stabStatusValue(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return stabBoundedStatus(int64(n))
	case int8:
		return stabBoundedStatus(int64(n))
	case int16:
		return stabBoundedStatus(int64(n))
	case int32:
		return stabBoundedStatus(int64(n))
	case int64:
		return stabBoundedStatus(n)
	case uint:
		if uint64(n) > 3 {
			return 0, false
		}
		return int(n), true
	case uint8:
		if uint64(n) > 3 {
			return 0, false
		}
		return int(n), true
	case uint16:
		if uint64(n) > 3 {
			return 0, false
		}
		return int(n), true
	case uint32:
		if uint64(n) > 3 {
			return 0, false
		}
		return int(n), true
	case uint64:
		if n > 3 {
			return 0, false
		}
		return int(n), true
	}
	return 0, false
}

func stabHasStatus(m ws.ProtoMsg) bool {
	if m.Header.Properties == nil {
		return false
	}
	_, ok := m.Header.Properties["status"]
	return ok
}

// stabStatus reads the canonical status from HEADER properties only.
func stabStatus(m ws.ProtoMsg) (int, bool) {
	if m.Header.Properties == nil {
		return 0, false
	}
	v, ok := m.Header.Properties["status"]
	if !ok {
		return 0, false
	}
	return stabStatusValue(v)
}

func stabRequireStatus(m ws.ProtoMsg, want int, label string) (int, bool) {
	st, ok := stabStatus(m)
	if !ok {
		return 0, false
	}
	if st != want {
		return st, false
	}
	return st, true
}

// stabHandleControlPing validates a generic CONTROL ping and answers it with a
// correlated CONTROL pong on the shared (serialized) writer. Callers run in the
// main receive/dispatch loops so all writes remain serialized; the reader
// goroutine never writes.
func stabHandleControlPing(c *websocket.Conn, m ws.ProtoMsg, progress *stabProgress, writeProgress func() error) error {
	if m.Header.Proto != ws.ProtoTypeControl {
		return fmt.Errorf("unexpected control ping protocol")
	}
	if m.Header.SessionID != stabSessionID {
		return fmt.Errorf("unexpected control ping session")
	}
	if m.Header.MsgType != "ping" {
		return fmt.Errorf("unexpected control message type")
	}
	if len(m.Body) != 0 {
		return fmt.Errorf("control ping body exceeded limit")
	}
	msg := ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypeControl,
			MsgType:   "pong",
			SessionID: stabSessionID,
		},
	}
	data, err := msgpack.Marshal(msg)
	if err != nil {
		return fmt.Errorf("cannot encode control pong")
	}
	if err := c.SetWriteDeadline(time.Now().Add(stabResponseWindow)); err != nil {
		return fmt.Errorf("cannot set control pong write deadline")
	}
	if err := c.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return fmt.Errorf("control pong not sent")
	}
	if progress != nil {
		progress.ControlPings++
		progress.ControlPongs++
	}
	if writeProgress != nil {
		if err := writeProgress(); err != nil {
			return err
		}
	}
	return nil
}

func stabWriteJSON(dir, name string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	f, err := os.CreateTemp(dir, "."+name+"-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func stabReader(c *websocket.Conn, budget time.Duration, out chan<- stabResp, done <-chan struct{}) {
	c.SetReadDeadline(time.Now().Add(budget))
	for {
		_, data, err := c.ReadMessage()
		if err != nil {
			select {
			case out <- stabResp{err: fmt.Errorf("read failed")}:
			case <-done:
			}
			return
		}
		var m ws.ProtoMsg
		if err := msgpack.Unmarshal(data, &m); err != nil {
			select {
			case out <- stabResp{err: fmt.Errorf("invalid message")}:
			case <-done:
			}
			return
		}
		select {
		case out <- stabResp{m: m}:
		case <-done:
			return
		}
	}
}

func stabSendResize(c *websocket.Conn) error {
	msg := ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypeShell,
			MsgType:   "resize",
			SessionID: stabSessionID,
			Properties: map[string]interface{}{
				"terminal_width":  101,
				"terminal_height": 37,
			},
		},
	}
	data, err := msgpack.Marshal(msg)
	if err != nil {
		return fmt.Errorf("cannot encode resize request")
	}
	if err := c.SetWriteDeadline(time.Now().Add(stabResizeWrite)); err != nil {
		return fmt.Errorf("cannot set resize write deadline")
	}
	if err := c.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return fmt.Errorf("resize request not sent")
	}
	return nil
}

func run(c *websocket.Conn, dir, scenario string) (result []string, err error) {
	if c == nil {
		return nil, fmt.Errorf("missing websocket connection")
	}
	if dir == "" {
		return nil, fmt.Errorf("missing work directory")
	}
	soak, err := stabSoakSeconds()
	if err != nil {
		return nil, err
	}
	soakDur := time.Duration(soak) * time.Second
	workDir := filepath.Join(dir, "work")
	if mkErr := os.MkdirAll(workDir, 0o755); mkErr != nil {
		return nil, fmt.Errorf("cannot prepare work directory")
	}

	p := &peer{c: c, proto: ws.ProtoTypeControl}
	if err := p.request("open", stabSessionID, ws.Open{Versions: []int{1}}); err != nil {
		return nil, fmt.Errorf("control open not sent")
	}
	if _, err := p.expect("accept", stabSessionID); err != nil {
		return nil, fmt.Errorf("control open not accepted")
	}
	p.proto = ws.ProtoTypeShell
	if err := p.send("new", stabSessionID, nil, nil); err != nil {
		return nil, fmt.Errorf("shell session not requested")
	}
	newMsg, err := p.expect("new", stabSessionID)
	if err != nil {
		return nil, fmt.Errorf("shell session not started")
	}
	if st, ok := stabStatus(newMsg); !ok || st != 1 {
		return nil, fmt.Errorf("shell session not ready")
	}

	respCh := make(chan stabResp, stabChanCap)
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		stabReader(c, soakDur+stabExtraSlack, respCh, done)
	}()

	var closeOnce sync.Once
	shutdown := func() {
		closeOnce.Do(func() { close(done) })
		_ = c.Close()
	}
	defer func() {
		shutdown()
		select {
		case <-finished:
		case <-time.After(stabCleanupWait):
			result = nil
			if err == nil {
				err = fmt.Errorf("stability reader did not stop")
			}
		}
	}()

	start := time.Now()
	endAt := start.Add(soakDur)
	progress := stabProgress{}
	writeProgress := func() error {
		progress.ElapsedSeconds = int(time.Since(start) / time.Second)
		if wErr := stabWriteJSON(dir, "stability-progress.json", progress); wErr != nil {
			return fmt.Errorf("cannot write stability progress")
		}
		return nil
	}

	pending := false
	pendingMarker := ""
	var pendingBuf bytes.Buffer
	pendingDeadline := time.Time{}
	expectResize := false
	resizeSent := false
	closingIssued := false
	seq := 1

	marker := fmt.Sprintf("STABM%d", seq)
	initial := "stty -echo; printf '" + stabOctal(marker+"\n") + "'\n"
	if err := p.send("shell", stabSessionID, []byte(initial), nil); err != nil {
		return nil, fmt.Errorf("initial command not sent")
	}
	pending = true
	pendingMarker = marker
	pendingBuf.Reset()
	pendingDeadline = start.Add(stabResponseWindow)
	if err := writeProgress(); err != nil {
		return nil, err
	}

	nextAt := start.Add(stabInitialIdle)
	if nextAt.After(endAt) {
		nextAt = endAt
	}

loop:
	for {
		var actionCh <-chan time.Time
		var deadlineCh <-chan time.Time
		if pending {
			deadlineCh = time.After(time.Until(pendingDeadline))
		} else {
			actionCh = time.After(time.Until(nextAt))
		}

		select {
		case r := <-respCh:
			if r.err != nil {
				return nil, fmt.Errorf("shell connection read failed")
			}
			m := r.m
			if m.Header.Proto == ws.ProtoTypeControl {
				if err := stabHandleControlPing(c, m, &progress, writeProgress); err != nil {
					return nil, err
				}
				continue
			}
			if m.Header.Proto != ws.ProtoTypeShell {
				return nil, fmt.Errorf("unexpected shell message protocol")
			}
			if m.Header.SessionID != stabSessionID {
				return nil, fmt.Errorf("unexpected shell message session")
			}
			switch m.Header.MsgType {
			case "ping":
				if _, ok := stabRequireStatus(m, 3, "shell ping"); !ok {
					return nil, fmt.Errorf("shell ping status invalid")
				}
				progress.Pings++
				if err := p.send("pong", stabSessionID, []byte{}, nil); err != nil {
					return nil, fmt.Errorf("shell pong not sent")
				}
				progress.Pongs++
				if err := writeProgress(); err != nil {
					return nil, err
				}
			case "stop":
				return nil, fmt.Errorf("unexpected shell stop")
			case "shell":
				if _, ok := stabRequireStatus(m, 1, "shell output"); !ok {
					return nil, fmt.Errorf("shell output status invalid")
				}
				if !pending {
					continue
				}
				if pendingBuf.Len()+len(m.Body) > stabOutputLimit {
					return nil, fmt.Errorf("shell output exceeded limit")
				}
				pendingBuf.Write(m.Body)
				if !bytes.Contains(pendingBuf.Bytes(), []byte(pendingMarker)) {
					continue
				}
				if expectResize {
					if !bytes.Contains(pendingBuf.Bytes(), []byte("37 101")) {
						return nil, fmt.Errorf("terminal resize not applied")
					}
					expectResize = false
					progress.ResizeVerified = true
				}
				progress.Commands++
				if err := writeProgress(); err != nil {
					return nil, err
				}
				pending = false
				pendingBuf.Reset()
				pendingMarker = ""
				closing := closingIssued
				closingIssued = false
				if progress.Commands == 1 {
					nextAt = start.Add(stabInitialIdle)
				} else {
					nextAt = time.Now().Add(stabFollowUp)
				}
				if nextAt.After(endAt) {
					nextAt = endAt
				}
				if closing {
					break loop
				}
			default:
				return nil, fmt.Errorf("unexpected shell message type")
			}
		case <-actionCh:
			if pending {
				continue
			}
			elapsed := time.Since(start)
			if elapsed > soakDur+stabExtraSlack {
				return nil, fmt.Errorf("soak duration exceeded without completion")
			}
			closing := elapsed >= soakDur
			if !resizeSent {
				if err := stabSendResize(c); err != nil {
					return nil, err
				}
				resizeSent = true
				expectResize = true
			}
			seq++
			marker := fmt.Sprintf("STABM%d", seq)
			var cmd strings.Builder
			if closing {
				cmd.WriteString("sleep 300 >/dev/null 2>&1 & ")
			}
			if expectResize {
				cmd.WriteString("stty size; ")
			}
			cmd.WriteString("printf '")
			cmd.WriteString(stabOctal(marker + "\n"))
			cmd.WriteString("'\n")
			if err := p.send("shell", stabSessionID, []byte(cmd.String()), nil); err != nil {
				return nil, fmt.Errorf("shell command not sent")
			}
			pending = true
			pendingMarker = marker
			pendingBuf.Reset()
			pendingDeadline = time.Now().Add(stabResponseWindow)
			closingIssued = closing
		case <-deadlineCh:
			return nil, fmt.Errorf("marker response timed out")
		}
	}

	if progress.Commands < 2 {
		return nil, fmt.Errorf("not enough successful shell commands")
	}
	if soakDur >= 90*time.Second && progress.Pings < 1 {
		return nil, fmt.Errorf("no shell heartbeat observed")
	}
	if time.Since(start) < soakDur {
		return nil, fmt.Errorf("soak duration not reached")
	}

	stopBody, err := msgpack.Marshal(stabStatusBody{Status: 1})
	if err != nil {
		return nil, fmt.Errorf("cannot encode stop request")
	}
	if err := p.send("stop", stabSessionID, stopBody, nil); err != nil {
		return nil, fmt.Errorf("stop request not sent")
	}
	stopDeadline := time.Now().Add(stabResponseWindow)
	stopped := false
	for !stopped {
		remain := time.Until(stopDeadline)
		if remain <= 0 {
			return nil, fmt.Errorf("shell stop not acknowledged")
		}
		select {
		case r := <-respCh:
			if r.err != nil {
				return nil, fmt.Errorf("shell connection read failed")
			}
			m := r.m
			if m.Header.Proto == ws.ProtoTypeControl {
				if err := stabHandleControlPing(c, m, &progress, writeProgress); err != nil {
					return nil, err
				}
				continue
			}
			if m.Header.Proto != ws.ProtoTypeShell {
				return nil, fmt.Errorf("unexpected stop-phase message protocol")
			}
			if m.Header.SessionID != stabSessionID {
				return nil, fmt.Errorf("unexpected stop-phase message session")
			}
			switch m.Header.MsgType {
			case "ping":
				if _, ok := stabRequireStatus(m, 3, "shell ping"); !ok {
					return nil, fmt.Errorf("shell ping status invalid")
				}
				progress.Pings++
				if err := p.send("pong", stabSessionID, []byte{}, nil); err != nil {
					return nil, fmt.Errorf("shell pong not sent")
				}
				progress.Pongs++
				if err := writeProgress(); err != nil {
					return nil, err
				}
			case "stop":
				if _, ok := stabRequireStatus(m, 1, "shell stop"); !ok {
					return nil, fmt.Errorf("shell stop status invalid")
				}
				stopped = true
			case "shell":
				if _, ok := stabRequireStatus(m, 1, "shell output"); !ok {
					return nil, fmt.Errorf("shell output status invalid")
				}
			default:
				return nil, fmt.Errorf("unexpected stop-phase message type")
			}
		case <-time.After(remain):
		}
	}

	p.proto = ws.ProtoTypeControl
	if err := p.send("ping", stabSessionID, []byte{}, nil); err != nil {
		return nil, fmt.Errorf("control ping not sent")
	}
	pongDeadline := time.Now().Add(stabResponseWindow)
	pongSeen := false
	for !pongSeen {
		remain := time.Until(pongDeadline)
		if remain <= 0 {
			return nil, fmt.Errorf("control pong not received")
		}
		select {
		case r := <-respCh:
			if r.err != nil {
				return nil, fmt.Errorf("connection read failed")
			}
			m := r.m
			if m.Header.Proto != ws.ProtoTypeControl {
				if m.Header.Proto == ws.ProtoTypeShell && m.Header.MsgType == "shell" {
					if m.Header.SessionID != stabSessionID {
						return nil, fmt.Errorf("unexpected queued shell output session")
					}
					if _, ok := stabRequireStatus(m, 1, "queued shell output"); !ok {
						return nil, fmt.Errorf("queued shell output status invalid")
					}
					continue
				}
				return nil, fmt.Errorf("unexpected control-phase message protocol")
			}
			if m.Header.SessionID != stabSessionID {
				return nil, fmt.Errorf("unexpected control message session")
			}
			switch m.Header.MsgType {
			case "pong":
				pongSeen = true
			case "ping":
				if err := stabHandleControlPing(c, m, &progress, writeProgress); err != nil {
					return nil, err
				}
				continue
			default:
				return nil, fmt.Errorf("unexpected control message type")
			}
		case <-time.After(remain):
		}
	}

	elapsedSeconds := int(time.Since(start) / time.Second)
	if elapsedSeconds < soak {
		return nil, fmt.Errorf("soak duration not reached")
	}
	if !progress.ResizeVerified {
		return nil, fmt.Errorf("terminal resize not verified")
	}
	progress.ElapsedSeconds = elapsedSeconds
	metrics := stabMetrics{
		Passed:         true,
		SoakSeconds:    soak,
		ElapsedSeconds: elapsedSeconds,
		Commands:       progress.Commands,
		Pings:          progress.Pings,
		Pongs:          progress.Pongs,
		ControlPings:   progress.ControlPings,
		ControlPongs:   progress.ControlPongs,
		ResizeVerified: progress.ResizeVerified,
	}
	if err := stabWriteJSON(dir, "stability-metrics.json", metrics); err != nil {
		return nil, fmt.Errorf("cannot write stability metrics")
	}
	if err := writeProgress(); err != nil {
		return nil, err
	}

	return []string{
		"stability-soak-seconds:" + strconv.Itoa(soak),
		"stability-commands:" + strconv.Itoa(progress.Commands),
		"stability-resize-37x101",
		"stability-shell-stop",
		"stability-control-ping-pong",
	}, nil
}
