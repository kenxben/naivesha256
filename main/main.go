package main

import (
	"flag"
	"fmt"
	sha "naivesha256"
)

func main() {
	s := flag.String("message", "", "Enter a message to hash with SHA-256 algorithm. Default: empty string")
	flag.Parse()
	h := sha.NewHash([]byte(*s))
	hashed := h.Hash()
	fmt.Printf("%x\n", hashed)
}
