package tls

import (
	"crypto/sha1"
	"testing"
)

func TestSsl30MAC_MAC(t *testing.T) {
	h := ssl30MAC{
		h:   sha1.New(),
		key: make([]byte, 1),
	}
	h.MAC([]byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5})
	h.Size()
	Warningf("test")
}
