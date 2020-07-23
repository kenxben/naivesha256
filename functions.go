package naivesha256

import (
	// "fmt"
	"encoding/binary"
	"math/bits"
)

// Ch function of SHA-256
func choose(x, y, z uint32) uint32 {
	return (x & y) ^ (^x & z)
}

// majority function of SHA-256
func majority(x, y, z uint32) uint32 {
	return (x & y) ^ (x & z) ^ (y & z)
}

// E0256 is the Upper Sigma 0 function for SHA-256
func e0256(x uint32) uint32 {
	return bits.RotateLeft32(x, -2) ^
		bits.RotateLeft32(x, -13) ^
		bits.RotateLeft32(x, -22)
}

// E1256 is the Upper Sigma 1 function for SHA-256
func e1256(x uint32) uint32 {
	return bits.RotateLeft32(x, -6) ^
		bits.RotateLeft32(x, -11) ^
		bits.RotateLeft32(x, -25)
}

// S0256 is the Lower Sigma 1 function for SHA-256
func s0256(x uint32) uint32 {
	return bits.RotateLeft32(x, -7) ^
		bits.RotateLeft32(x, -18) ^
		x>>3
}

// S1256 is the Lower Sigma 1 function for SHA-256
func s1256(x uint32) uint32 {
	return bits.RotateLeft32(x, -17) ^
		bits.RotateLeft32(x, -19) ^
		x>>10
}

// Padding message to length multiple of 512
func padding(m []byte) []byte {

	l := 8 * len(m) // length in bits
	//n0 :=
	p := (l + 1) / 512         // p * 512 = (l+1) - remainder (remainder < 512)
	k := p*512 + 448 - (l + 1) // p * 512 + 448 = (l+1) + k (l+1+k = 448mod512)
	kbytes := (k + 1) / 8

	if (k+1)%8 != 0 {
		panic("Error: Some length problem with padding")
	}

	pad := make([]byte, kbytes) // padding full of zeros and desired length

	pad[0] = 1 << 7 // set first byte in padding to start with 1

	lbytes := make([]byte, 8) // length l in 64 bits (8 bytes)
	lb := uint64(l)
	binary.BigEndian.PutUint64(lbytes, lb) // from uitn64 to []byte

	s := append(m, pad...) // 1 followed by k zeros
	s = append(s, lbytes...)

	// fmt.Printf("Message: %s\nPadded message: %x\n", m, s)
	return s
}

// Parsing32 padded message s into blocks of m=512 bits length with 16 words.
func parsing(s []byte) [][16]uint32 {

	if len(s) < 512/8 {
		panic("Error: Trying to parse a message of length < 512")
	}
	nb := 4 // number of bytes per word. = 4 for SHA-256

	var words []uint32
	var blocks [][16]uint32

	// parse into words 8*nb bits length
	for i := 0; i < len(s); i = i + nb {
		words = append(words, binary.BigEndian.Uint32(s[i:]))
	}

	// 16 words per block
	for i := 0; i < len(words); i = i + 16 {
		var b [16]uint32 // block
		copy(b[:], words[i:i+16])
		blocks = append(blocks, b)
	}
	// fmt.Printf("%v\n", blocks)
	return blocks
}

// PrepareSchedule receives a block and returns a schedule of 64 32bit words
func prepareSchedule(m [16]uint32) [64]uint32 {
	var w [64]uint32

	copy(w[0:16], m[0:16])

	for t := 16; t < 64; t++ {
		w[t] = s1256(w[t-2]) + w[t-7] + s0256(w[t-15]) + w[t-16]
	}
	return w
}

// HashComputation computes one iteration (one block)
func hashComputation(w [64]uint32, hash [8]uint32) [8]uint32 {
	var outhash [8]uint32
	kconst := Kconst()

	a := hash[0]
	b := hash[1]
	c := hash[2]
	d := hash[3]
	e := hash[4]
	f := hash[5]
	g := hash[6]
	h := hash[7]

	for t := 0; t < 64; t++ {

		t1 := h + e1256(e) + choose(e, f, g) + kconst[t] + w[t]
		t2 := e0256(a) + majority(a, b, c)
		h = g
		g = f
		f = e
		e = d + t1
		d = c
		c = b
		b = a
		a = t1 + t2
		// fmt.Printf("%v: %x, %x, %x, %x, %x, %x, %x, %x\n", t,a,b,c,d,e,f,g,h)
	}

	outhash[0] = a + hash[0]
	outhash[1] = b + hash[1]
	outhash[2] = c + hash[2]
	outhash[3] = d + hash[3]
	outhash[4] = e + hash[4]
	outhash[5] = f + hash[5]
	outhash[6] = g + hash[6]
	outhash[7] = h + hash[7]

	return outhash
}

// Hash struct with Hash function
type Hash struct {
	message []byte
}

// NewHash creates a new Hash struct to apply the Hash function
func NewHash(message []byte) Hash {
	return Hash{message}
}

// Hash returns SHA-256 hash of message
func (h Hash) Hash() [8]uint32 {
	s := padding(h.message)
	p := parsing(s)

	// initialize hash
	hash := InitialHash()

	for i := 1; i <= len(p); i++ {
		w := prepareSchedule(p[i-1])

		hash = hashComputation(w, hash)
	}

	// hashed := make([]byte, 8*4)

	// for i, h := range hash {
	//     binary.BigEndian.PutUint32(hashed[4*i:], h)
	// }

	return hash // hashed
}
