package main

import (
	"fmt"
	sha "naivesha256"
	"flag"
)

func main() {
	s := flag.String("message", "", "Enter a message to hash with SHA-256 algorithm. Default: empty string")
	flag.Parse()

	hashed := sha.Sha256([]byte(*s))

	fmt.Printf("%x\n", hashed)
}
