// Package tunnel carries application traffic over transport streams: the client
// exposes port-forwards and a SOCKS5 proxy, the server dials the requested
// target and relays bytes. Each new stream begins with a small authenticated
// connect header.
package tunnel

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	protoVersion = 1

	cmdConnectTCP = 1
	cmdConnectUDP = 2
	cmdHello      = 3 // authenticated connectivity check at session start; carries no target

	// address types
	atypBackendPort = 0 // no address; server uses its configured backend IP
	atypIPv4        = 1
	atypDomain      = 3
	atypIPv6        = 4

	// response status codes
	statusOK       = 0
	statusAuthFail = 1
	statusDialFail = 2
	statusBadReq   = 3

	maxHeaderLen = 512
)

var be = binary.BigEndian

// connectReq is the first message on every stream.
type connectReq struct {
	Cmd  byte
	Atyp byte
	Host string // for IPv4/IPv6/domain; empty for backend-port
	Port uint16
}

func hmacTag(psk string, header []byte) []byte {
	m := hmac.New(sha256.New, []byte("gfk-stream-v1:"+psk))
	m.Write(header)
	return m.Sum(nil)
}

// encodeHeader serializes the request fields (without the auth tag).
func (r connectReq) encodeHeader() ([]byte, error) {
	buf := []byte{protoVersion, r.Cmd, r.Atyp}
	switch r.Atyp {
	case atypBackendPort:
	case atypIPv4:
		ip := net.ParseIP(r.Host).To4()
		if ip == nil {
			return nil, fmt.Errorf("bad IPv4 %q", r.Host)
		}
		buf = append(buf, ip...)
	case atypIPv6:
		ip := net.ParseIP(r.Host).To16()
		if ip == nil {
			return nil, fmt.Errorf("bad IPv6 %q", r.Host)
		}
		buf = append(buf, ip...)
	case atypDomain:
		if len(r.Host) == 0 || len(r.Host) > 255 {
			return nil, fmt.Errorf("bad domain length %d", len(r.Host))
		}
		buf = append(buf, byte(len(r.Host)))
		buf = append(buf, r.Host...)
	default:
		return nil, fmt.Errorf("bad atyp %d", r.Atyp)
	}
	var p [2]byte
	be.PutUint16(p[:], r.Port)
	buf = append(buf, p[:]...)
	return buf, nil
}

// writeConnectReq writes tag(32) + len(2) + header.
func writeConnectReq(w io.Writer, psk string, r connectReq) error {
	header, err := r.encodeHeader()
	if err != nil {
		return err
	}
	tag := hmacTag(psk, header)
	out := make([]byte, 0, 32+2+len(header))
	out = append(out, tag...)
	var l [2]byte
	be.PutUint16(l[:], uint16(len(header)))
	out = append(out, l[:]...)
	out = append(out, header...)
	_, err = w.Write(out)
	return err
}

// readConnectReq reads and authenticates a connect header.
func readConnectReq(r io.Reader, psk string) (connectReq, error) {
	var req connectReq
	tag := make([]byte, 32)
	if _, err := io.ReadFull(r, tag); err != nil {
		return req, err
	}
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return req, err
	}
	n := be.Uint16(l[:])
	if n < 5 || n > maxHeaderLen {
		return req, fmt.Errorf("bad header length %d", n)
	}
	header := make([]byte, n)
	if _, err := io.ReadFull(r, header); err != nil {
		return req, err
	}
	if !hmac.Equal(tag, hmacTag(psk, header)) {
		return req, errAuth
	}
	if header[0] != protoVersion {
		return req, fmt.Errorf("bad version %d", header[0])
	}
	req.Cmd = header[1]
	req.Atyp = header[2]
	pos := 3
	switch req.Atyp {
	case atypBackendPort:
	case atypIPv4:
		if len(header) < pos+4+2 {
			return req, errBadHeader
		}
		req.Host = net.IP(header[pos : pos+4]).String()
		pos += 4
	case atypIPv6:
		if len(header) < pos+16+2 {
			return req, errBadHeader
		}
		req.Host = net.IP(header[pos : pos+16]).String()
		pos += 16
	case atypDomain:
		if len(header) < pos+1 {
			return req, errBadHeader
		}
		dl := int(header[pos])
		pos++
		if len(header) < pos+dl+2 {
			return req, errBadHeader
		}
		req.Host = string(header[pos : pos+dl])
		pos += dl
	default:
		return req, fmt.Errorf("bad atyp %d", req.Atyp)
	}
	if len(header) < pos+2 {
		return req, errBadHeader
	}
	req.Port = be.Uint16(header[pos : pos+2])
	return req, nil
}

func writeStatus(w io.Writer, status byte) error {
	_, err := w.Write([]byte{status})
	return err
}

func readStatus(r io.Reader) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

// writeDatagram frames one UDP datagram over a stream as len(2)+payload.
func writeDatagram(w io.Writer, data []byte) error {
	if len(data) > 65535 {
		return fmt.Errorf("datagram too large: %d", len(data))
	}
	var l [2]byte
	be.PutUint16(l[:], uint16(len(data)))
	if _, err := w.Write(l[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// readDatagram reads one length-framed UDP datagram from a stream.
func readDatagram(r io.Reader, buf []byte) (int, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return 0, err
	}
	n := int(be.Uint16(l[:]))
	if n > len(buf) {
		return 0, fmt.Errorf("datagram %d exceeds buffer %d", n, len(buf))
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return 0, err
	}
	return n, nil
}

var (
	errAuth      = fmt.Errorf("stream auth failed")
	errBadHeader = fmt.Errorf("malformed connect header")
)
