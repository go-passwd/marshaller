package marshaller

import (
	"bytes"
	"fmt"
	"html/template"
	"regexp"
	"strconv"

	"github.com/go-passwd/hasher"
)

// Marshaller vars
var (
	marshalTemplate  = template.Must(template.New("marshalTemplate").Parse("{{.Code}}{{.Separator}}{{.Iterations}}{{.Separator}}{{.Salt}}{{.Separator}}{{.Password}}"))
	unmarshalPattern = template.Must(template.New("unmarshalPattern").Parse("^(?P<code>\\w+)\\{{.Separator}}(?P<iterations>\\d+)\\{{.Separator}}(?P<salt>\\w*)\\{{.Separator}}(?P<password>\\w+)$"))
)

// Marshaller defines interface for marshal and unmarshal hasher
type Marshaller interface {
	Marshal(hshr hasher.Hasher) (string, error)

	Unmarshal(string) (hasher.Hasher, error)
}

// Marshaller template params struct
type templateParams struct {
	Code       string
	Iterations int
	Salt       string
	Password   string
	Separator  string
}

type encodeToStringFunc func([]byte) string

func marshal(h hasher.Hasher, separator string, encodeFunc encodeToStringFunc) (string, error) {
	var params templateParams
	switch h.Code() {
	case hasher.TypePlain:
		hh := h.(*hasher.PlainHasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: 0,
			Salt:       "",
			Password:   encodeFunc(*hh.Password),
		}
	case hasher.TypeMD5:
		hh := h.(*hasher.MD5Hasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: *hh.Iter,
			Salt:       *hh.Salt,
			Password:   encodeFunc(*hh.Password),
		}
	case hasher.TypeSHA1:
		hh := h.(*hasher.SHA1Hasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: *hh.Iter,
			Salt:       *hh.Salt,
			Password:   encodeFunc(*hh.Password),
		}
	case hasher.TypeSHA224:
		hh := h.(*hasher.SHA224Hasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: *hh.Iter,
			Salt:       *hh.Salt,
			Password:   encodeFunc(*hh.Password),
		}
	case hasher.TypeSHA256:
		hh := h.(*hasher.SHA256Hasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: *hh.Iter,
			Salt:       *hh.Salt,
			Password:   encodeFunc(*hh.Password),
		}
	case hasher.TypeSHA384:
		hh := h.(*hasher.SHA384Hasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: *hh.Iter,
			Salt:       *hh.Salt,
			Password:   encodeFunc(*hh.Password),
		}
	case hasher.TypeSHA512:
		hh := h.(*hasher.SHA512Hasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: *hh.Iter,
			Salt:       *hh.Salt,
			Password:   encodeFunc(*hh.Password),
		}
	case hasher.TypeSHA512_224:
		hh := h.(*hasher.SHA512_224Hasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: *hh.Iter,
			Salt:       *hh.Salt,
			Password:   encodeFunc(*hh.Password),
		}
	case hasher.TypeSHA512_256:
		hh := h.(*hasher.SHA512_256Hasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: *hh.Iter,
			Salt:       *hh.Salt,
			Password:   encodeFunc(*hh.Password),
		}
	}
	params.Separator = separator
	buf := bytes.NewBufferString("")
	err := marshalTemplate.ExecuteTemplate(buf, "marshalTemplate", params)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

type decodeStringFunc func(string) ([]byte, error)

func unmarshal(s, separator string, decodeFunc decodeStringFunc) (hasher.Hasher, error) {
	buf := bytes.NewBufferString("")
	params := templateParams{Separator: separator}
	err := unmarshalPattern.ExecuteTemplate(buf, "unmarshalPattern", params)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(buf.String())
	submatch := re.FindStringSubmatch(s)
	if submatch == nil {
		return nil, fmt.Errorf("cannot unmarshal string %s", s)
	}

	password, err := decodeFunc(submatch[4])
	if err != nil {
		return nil, err
	}
	iter, err := strconv.Atoi(submatch[2])
	if err != nil {
		return nil, err
	}

	return hasher.NewWithParams(submatch[1], &iter, &submatch[3], &password)
}
