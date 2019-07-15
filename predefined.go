package marshaller

// DjangoMarshaller stores passwords in Django like format
var DjangoMarshaller = HexMarshaller{Separator: "$"}

// var DjangoMarshaller = HexMarshaller{Template: "{{.Code}}${{.Iterations}}${{.Salt}}${{.Password}}", Pattern: "^(\\w+)\\$(\\d+)\\$(\\w*)\\$(\\w+)$"}
