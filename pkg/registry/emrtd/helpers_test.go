package emrtd

import (
	"crypto/rand"
	"encoding/pem"
	"io"
	"log/slog"

	"github.com/sirosfoundation/go-cryptoutil"
	"github.com/sirosfoundation/go-cryptoutil/brainpool"
)

func testExt() *cryptoutil.Extensions {
	ext := cryptoutil.New()
	brainpool.Register(ext)
	return ext
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type testRand struct{}

func (testRand) Read(b []byte) (int, error) { return rand.Read(b) }

func pemBytes(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}
