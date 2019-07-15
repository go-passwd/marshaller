package marshaller

import (
	"html/template"

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
