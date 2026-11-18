package main

import (
	"bytes"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/mendersoftware/go-lib-micro/ws"
	ft "github.com/mendersoftware/go-lib-micro/ws/filetransfer"
	"github.com/vmihailenco/msgpack/v5"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func rejectHeader(p *peer, scenario string) ([]string, error) {
	m := ws.ProtoMsg{Header: ws.ProtoHdr{Proto: ws.ProtoTypeShell, MsgType: "new", SessionID: "bad", Properties: map[string]interface{}{}}}
	switch scenario {
	case "header-sid":
		m.Header.SessionID = strings.Repeat("x", 129)
	case "header-type":
		m.Header.MsgType = strings.Repeat("x", 129)
	case "header-count":
		for i := 0; i < 33; i++ {
			m.Header.Properties[fmt.Sprintf("key-%d", i)] = nil
		}
	case "header-key":
		m.Header.Properties[strings.Repeat("x", 129)] = nil
	case "header-routing":
		m.Header.Properties["connection_id"] = strings.Repeat("x", 129)
	case "header-routing-type":
		m.Header.Properties["msgid"] = 123
	default:
		return nil, fmt.Errorf("unknown header case")
	}
	data, err := msgpack.Marshal(m)
	if err != nil {
		return nil, err
	}
	p.c.SetWriteDeadline(time.Now().Add(4 * time.Second))
	if err = p.c.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return nil, err
	}
	reply, err := p.next()
	if err == nil {
		return nil, fmt.Errorf("invalid header reached application dispatch: %+v", reply.Header)
	}
	if _, ok := err.(*websocket.CloseError); !ok {
		return nil, fmt.Errorf("expected transport closure, got %v", err)
	}
	return []string{scenario + " rejected by closing transport before application response"}, nil
}

func uploadErrors(p *peer, assets, path string) ([]string, error) {
	old := []byte("original-not-replaced")
	if err := os.WriteFile(path, old, 0600); err != nil {
		return nil, err
	}
	cases := []struct {
		name   string
		offset *int64
		data   []byte
	}{}
	negative, gap, zero := int64(-1), int64(1), int64(0)
	cases = append(cases, struct {
		name   string
		offset *int64
		data   []byte
	}{"negative", &negative, []byte("x")}, struct {
		name   string
		offset *int64
		data   []byte
	}{"gap", &gap, []byte("x")}, struct {
		name   string
		offset *int64
		data   []byte
	}{"oversize", &zero, []byte("123456")}, struct {
		name   string
		offset *int64
		data   []byte
	}{"short-eof", &zero, nil}, struct {
		name   string
		offset *int64
		data   []byte
	}{"missing-offset", nil, []byte("x")})
	for _, item := range cases {
		size := int64(5)
		if err := p.request("put_file", "reused", ft.UploadRequest{Path: &path, Size: &size}); err != nil {
			return nil, err
		}
		if err := p.ack("reused", 0); err != nil {
			return nil, err
		}
		if err := p.send("file_chunk", "reused", item.data, item.offset); err != nil {
			return nil, err
		}
		// Async worker failures correlate with the original put_file request,
		// as in the reference FileUploadHandler defer/Error path.
		if err := p.expectError("put_file", "reused"); err != nil {
			return nil, fmt.Errorf("%s: %w", item.name, err)
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, old) {
			return nil, fmt.Errorf("%s changed old destination", item.name)
		}
		items, err := os.ReadDir(assets)
		if err != nil || len(items) != 1 {
			return nil, fmt.Errorf("%s left stage file", item.name)
		}
	}
	foreign := uint32(os.Getuid() + 1)
	if err := p.request("put_file", "foreign", ft.UploadRequest{Path: &path, UID: &foreign}); err != nil {
		return nil, err
	}
	if err := p.expectError("put_file", "foreign"); err != nil {
		return nil, err
	}
	link := filepath.Join(assets, "upload-link")
	if err := os.Symlink(path, link); err != nil {
		return nil, err
	}
	if err := p.request("put_file", "link", ft.UploadRequest{Path: &link}); err != nil {
		return nil, err
	}
	if err := p.expectError("put_file", "link"); err != nil {
		return nil, err
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, old) {
		return nil, fmt.Errorf("rejected metadata upload altered destination")
	}
	return []string{"negative/gapped/missing offsets and declared-size violations rejected", "each terminal error cleans staging before response and permits same-key reuse", "foreign ownership and symlink destinations rejected", "old destination unchanged after all failures"}, nil
}
