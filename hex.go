package marshaller

import (
	"encoding/hex"

	"github.com/go-passwd/hasher"
)

// HexMarshaller stores password in HEX
type HexMarshaller struct {
	Separator string
}

// Marshal hasher.Hasher to string
func (m *HexMarshaller) Marshal(h hasher.Hasher) (string, error) {
	return marshal(h, m.Separator, encodeToStringFunc(hex.EncodeToString))
}

// Unmarshal string to Hasher
func (m *HexMarshaller) Unmarshal(s string) (hasher.Hasher, error) {
	return unmarshal(s, m.Separator, hex.DecodeString)
}
