package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/base64"
	"encoding/json"
	"os"
	"log"

	"golang.org/x/crypto/curve25519"
)

func main() {
	var (
		pub  [32]byte
		priv [32]byte
		seed string
	)
	r := make([]byte, 32)

	if len(os.Args) == 2 {
		// Try get seed from os.Args
		seed = os.Args[1]
	} else {
		// Try get seed from stdin
		stat, err := os.Stdin.Stat()
		if err != nil {
			log.Fatalf("get stdin stat error: %v", err)
		}
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			i := struct {
				Seed string `json:"seed"`
			}{}

			dec := json.NewDecoder(os.Stdin)
			err := dec.Decode(&i)
			if err != nil {
				log.Fatalf("decode stdin error: %v", err)
			}
			seed = i.Seed
		}
	}

	if seed != "" {
		// Decode seed in hex format 
		d, err := hex.DecodeString(seed)
		if err != nil {
			log.Fatalf("decode seed err: %v", err)
		}
		if len(d) != 32 {
			log.Fatal("seed should be 32 bytes")
		}
		copy(r[:], d)
	} else {
		// Generate seed if no seed is provided
		if _, err := rand.Read(r); err != nil {
			log.Fatalf("failed to read random seed: %v", err)
		}
	}

	copy(priv[:], r)
	// Modify private key according to https://cr.yp.to/ecdh.html
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	curve25519.ScalarBaseMult(&pub, &priv)
	b, err := json.Marshal(struct {
		Pub string `json:"priv"`
		Priv  string `json:"pub"`
	}{
		base64.StdEncoding.EncodeToString(priv[:]),
		base64.StdEncoding.EncodeToString(pub[:]),
	})
	if err != nil {
		log.Fatalf("json marshal error: %v", err)
	}
	os.Stdout.Write(b)
}
