package marshaler

// DjangoMarshaler stores passwords in Django like format
var DjangoMarshaler = HexMarshaler{Separator: "$"}

// var DjangoMarshaler = HexMarshaler{Template: "{{.Code}}${{.Iterations}}${{.Salt}}${{.Password}}", Pattern: "^(\\w+)\\$(\\d+)\\$(\\w*)\\$(\\w+)$"}
