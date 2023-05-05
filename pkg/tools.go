package pkg

import (
	"math/rand"
	"time"
)

const str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func Random(length int) string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = str[r.Intn(len(str))]
	}
	return string(b)
}
