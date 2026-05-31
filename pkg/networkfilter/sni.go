package networkfilter

import (
	"encoding/binary"
	"fmt"
	"io"
)

// PeekSNI reads a TLS ClientHello from r and returns the SNI hostname.
func PeekSNI(r io.Reader) (string, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return "", nil, fmt.Errorf("reading TLS header: %w", err)
	}
	if header[0] != 0x16 {
		return "", header, fmt.Errorf("not a TLS handshake record (type=%02x)", header[0])
	}
	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLen > 16384 {
		return "", header, fmt.Errorf("TLS record too large (%d)", recordLen)
	}
	body := make([]byte, recordLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return "", header, fmt.Errorf("reading TLS record body: %w", err)
	}
	raw := append(header, body...)

	sni, err := extractSNI(body)
	if err != nil {
		return "", raw, err
	}
	return sni, raw, nil
}

func extractSNI(data []byte) (string, error) {
	if len(data) < 4 {
		return "", fmt.Errorf("handshake record too short")
	}
	if data[0] != 0x01 {
		return "", fmt.Errorf("not a ClientHello (type=%02x)", data[0])
	}
	hsLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if 4+hsLen > len(data) {
		return "", fmt.Errorf("ClientHello truncated")
	}
	hello := data[4 : 4+hsLen]

	if len(hello) < 35 {
		return "", fmt.Errorf("ClientHello too short")
	}
	pos := 34
	sessionIDLen := int(hello[pos])
	pos++
	pos += sessionIDLen
	if pos+2 > len(hello) {
		return "", fmt.Errorf("ClientHello truncated at cipher suites")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if pos+1 > len(hello) {
		return "", fmt.Errorf("ClientHello truncated at compression methods")
	}
	compressionLen := int(hello[pos])
	pos++
	pos += compressionLen
	if pos+2 > len(hello) {
		return "", fmt.Errorf("no extensions in ClientHello")
	}
	extLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2
	extEnd := pos + extLen
	if extEnd > len(hello) {
		return "", fmt.Errorf("extensions length overflow")
	}
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(hello[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(hello[pos+2 : pos+4]))
		pos += 4
		if extType == 0x0000 {
			sni, err := parseSNIExtension(hello[pos : pos+extDataLen])
			if err != nil {
				return "", err
			}
			return sni, nil
		}
		pos += extDataLen
	}
	return "", fmt.Errorf("SNI extension not found")
}

func parseSNIExtension(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("SNI extension too short")
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	data = data[2:]
	if listLen > len(data) {
		return "", fmt.Errorf("SNI list length overflow")
	}
	pos := 0
	for pos+3 <= listLen {
		nameType := data[pos]
		nameLen := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		pos += 3
		if nameType == 0x00 {
			if pos+nameLen > len(data) {
				return "", fmt.Errorf("SNI hostname truncated")
			}
			return string(data[pos : pos+nameLen]), nil
		}
		pos += nameLen
	}
	return "", fmt.Errorf("no host_name in SNI list")
}
