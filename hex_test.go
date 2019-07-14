package marshaler

import (
	"testing"

	"github.com/go-passwd/hasher"
	"github.com/stretchr/testify/assert"
)

var (
	iter = 10
	salt = "salt"
)

const (
	password           = "password"
	passwordPlain      = "plain$0$$70617373776f7264"
	passwordMD5        = "md5$10$salt$1446572e0a1e0d275b6d1ec51d61d5b1"
	passwordSHA1       = "sha1$10$salt$0c567ff217a99b516d5634b2cb92282b21c47831"
	passwordSHA224     = "sha224$10$salt$dbe00a849ca8e1dce3a43746805241d291bb04aa52668ac0ab6ccf00"
	passwordSHA256     = "sha256$10$salt$f71b3ce092de12327025cd57fa3cf74c6a6eecc2cb8cb7514dd2fc57698e734e"
	passwordSHA384     = "sha384$10$salt$4a36c382e1bfc7c7decada7ff17754f1fd51350d3f73a3a109ae7f5220bff4ca81d8a9ad70e6174b18b1751ea01425a0"
	passwordSHA512     = "sha512$10$salt$39ab7c979fea0c9ff5bb58b0d6009a19594892910ec2bcbc37eacb803f60bb31546b7ff8f8cb3364b08ddedbbb7ef08aa46988e1656432f0a3d25e8cd3a5ad58"
	passwordSHA512_224 = "sha512_224$10$salt$9295ecc8e4e80586a8a4fd67c4259d77edcaee16b4b83426ec79658d"
	passwordSHA512_256 = "sha512_256$10$salt$28ffd44b7cd5649e707a7290c3e84c2db985e529d1abf86c74185bb259aa2151"
)

var m = HexMarshaler{
	Separator: "$",
}

func TestHexMarshaler_Marshal_plain(t *testing.T) {
	h := hasher.PlainHasher{}
	h.SetPassword(password)
	s, err := m.Marshal(&h)
	assert.Nil(t, err)
	assert.Equal(t, passwordPlain, s)
}

func TestHexMarshaler_Unmarshal_plain(t *testing.T) {
	h, err := m.Unmarshal(passwordPlain)
	assert.Nil(t, err)
	assert.True(t, h.Check(password))
}

func TestHexMarshaler_Marshal_md5(t *testing.T) {
	h := hasher.MD5Hasher{Iter: &iter, Salt: &salt}
	h.SetPassword(password)
	s, err := m.Marshal(&h)
	assert.Nil(t, err)
	assert.Equal(t, passwordMD5, s)
}

func TestHexMarshaler_Unmarshal_md5(t *testing.T) {
	h, err := m.Unmarshal(passwordMD5)
	assert.Nil(t, err)
	assert.True(t, h.Check(password))
}

func TestHexMarshaler_Marshal_sha1(t *testing.T) {
	h := hasher.SHA1Hasher{Iter: &iter, Salt: &salt}
	h.SetPassword(password)
	s, err := m.Marshal(&h)
	assert.Nil(t, err)
	assert.Equal(t, passwordSHA1, s)
}

func TestHexMarshaler_Unmarshal_sha1(t *testing.T) {
	h, err := m.Unmarshal(passwordSHA1)
	assert.Nil(t, err)
	assert.True(t, h.Check(password))
}

func TestHexMarshaler_Marshal_sha224(t *testing.T) {
	h := hasher.SHA224Hasher{Iter: &iter, Salt: &salt}
	h.SetPassword(password)
	s, err := m.Marshal(&h)
	assert.Nil(t, err)
	assert.Equal(t, passwordSHA224, s)
}

func TestHexMarshaler_Unmarshal_sha224(t *testing.T) {
	h, err := m.Unmarshal(passwordSHA224)
	assert.Nil(t, err)
	assert.True(t, h.Check(password))
}

func TestHexMarshaler_Marshal_sha256(t *testing.T) {
	h := hasher.SHA256Hasher{Iter: &iter, Salt: &salt}
	h.SetPassword(password)
	s, err := m.Marshal(&h)
	assert.Nil(t, err)
	assert.Equal(t, passwordSHA256, s)
}

func TestHexMarshaler_Unmarshal_sha256(t *testing.T) {
	h, err := m.Unmarshal(passwordSHA256)
	assert.Nil(t, err)
	assert.True(t, h.Check(password))
}

func TestHexMarshaler_Marshal_sha384(t *testing.T) {
	h := hasher.SHA384Hasher{Iter: &iter, Salt: &salt}
	h.SetPassword(password)
	s, err := m.Marshal(&h)
	assert.Nil(t, err)
	assert.Equal(t, passwordSHA384, s)
}

func TestHexMarshaler_Unmarshal_sha384(t *testing.T) {
	h, err := m.Unmarshal(passwordSHA384)
	assert.Nil(t, err)
	assert.True(t, h.Check(password))
}

func TestHexMarshaler_Marshal_sha512(t *testing.T) {
	h := hasher.SHA512Hasher{Iter: &iter, Salt: &salt}
	h.SetPassword(password)
	s, err := m.Marshal(&h)
	assert.Nil(t, err)
	assert.Equal(t, passwordSHA512, s)
}

func TestHexMarshaler_Unmarshal_sha512(t *testing.T) {
	h, err := m.Unmarshal(passwordSHA512)
	assert.Nil(t, err)
	assert.True(t, h.Check(password))
}

func TestHexMarshaler_Marshal_sha512_224(t *testing.T) {
	h := hasher.SHA512_224Hasher{Iter: &iter, Salt: &salt}
	h.SetPassword(password)
	s, err := m.Marshal(&h)
	assert.Nil(t, err)
	assert.Equal(t, passwordSHA512_224, s)
}

func TestHexMarshaler_Unmarshal_sha512_224(t *testing.T) {
	h, err := m.Unmarshal(passwordSHA512_224)
	assert.Nil(t, err)
	assert.True(t, h.Check(password))
}

func TestHexMarshaler_Marshal_sha512_256(t *testing.T) {
	h := hasher.SHA512_256Hasher{Iter: &iter, Salt: &salt}
	h.SetPassword(password)
	s, err := m.Marshal(&h)
	assert.Nil(t, err)
	assert.Equal(t, passwordSHA512_256, s)
}

func TestHexMarshaler_Unmarshal_sha512_256(t *testing.T) {
	h, err := m.Unmarshal(passwordSHA512_256)
	assert.Nil(t, err)
	assert.True(t, h.Check(password))
}

func TestHexMarshaler_Unmarshal_error(t *testing.T) {
	m := HexMarshaler{
		Separator: ":",
	}
	h, err := m.Unmarshal(passwordSHA512)
	assert.NotNil(t, err)
	assert.Nil(t, h)

	m = HexMarshaler{
		Separator: "$",
	}
	h, err = m.Unmarshal("sha512$10$salt$q")
	assert.NotNil(t, err)
	assert.Nil(t, h)

	h, err = m.Unmarshal("sha512$99999999999999999999999999999999999999999999999999999999999999999$salt$39ab7c979fea0c9ff5bb58b0d6009a19594892910ec2bcbc37eacb803f60bb31546b7ff8f8cb3364b08ddedbbb7ef08aa46988e1656432f0a3d25e8cd3a5ad58")
	assert.NotNil(t, err)
	assert.Nil(t, h)

	h, err = m.Unmarshal("sha5$20$salt$39ab7c979fea0c9ff5bb58b0d6009a19594892910ec2bcbc37eacb803f60bb31546b7ff8f8cb3364b08ddedbbb7ef08aa46988e1656432f0a3d25e8cd3a5ad58")
	assert.NotNil(t, err)
	assert.Nil(t, h)
}
