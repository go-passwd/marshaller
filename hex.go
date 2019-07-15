package marshaller

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"

	"github.com/go-passwd/hasher"
)

// HexMarshaller stores password in HEX
type HexMarshaller struct {
	Separator string
}

// Marshal hasher.Hasher to string
func (m *HexMarshaller) Marshal(h hasher.Hasher) (string, error) {
		}
	case hasher.TypeSHA384:
		hh := h.(*hasher.SHA384Hasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: *hh.Iter,
			Salt:       *hh.Salt,
			Password:   hex.EncodeToString(*hh.Password),
		}
	case hasher.TypeSHA512:
		hh := h.(*hasher.SHA512Hasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: *hh.Iter,
			Salt:       *hh.Salt,
			Password:   hex.EncodeToString(*hh.Password),
		}
	case hasher.TypeSHA512_224:
		hh := h.(*hasher.SHA512_224Hasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: *hh.Iter,
			Salt:       *hh.Salt,
			Password:   hex.EncodeToString(*hh.Password),
		}
	case hasher.TypeSHA512_256:
		hh := h.(*hasher.SHA512_256Hasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: *hh.Iter,
			Salt:       *hh.Salt,
			Password:   hex.EncodeToString(*hh.Password),
		}
	}
	params.Separator = m.Separator
	buf := bytes.NewBufferString("")
	err := marshalTemplate.ExecuteTemplate(buf, "marshalTemplate", params)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// Unmarshal string to Hasher
func (m *HexMarshaller) Unmarshal(s string) (hasher.Hasher, error) {
	buf := bytes.NewBufferString("")
	params := templateParams{Separator: m.Separator}
	err := unmarshalPattern.ExecuteTemplate(buf, "unmarshalPattern", params)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(buf.String())
	submatch := re.FindStringSubmatch(s)
	if submatch == nil {
		return nil, fmt.Errorf("cannot unmarshal string %s", s)
	}

	password, err := hex.DecodeString(submatch[4])
	if err != nil {
		return nil, err
	}
	iter, err := strconv.Atoi(submatch[2])
	if err != nil {
		return nil, err
	}

	return hasher.New(submatch[1], &iter, &submatch[3], &password)
}
