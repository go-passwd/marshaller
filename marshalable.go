package marshaller

// Marshalable defines interface for hasher who can be marshalable
type Marshalable interface {
	HasherCode() string
	Iterations() int
	Salt() string
	Password() []byte
}
