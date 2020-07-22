package naivesha256

import (
	// "fmt"
	"math/bits"
    "encoding/binary"
)

// Ch function of SHA-256
func Ch(x, y, z uint32) uint32 {
	return (x & y) ^ (^x & z)
}

// Maj function of SHA-256
func Maj(x, y, z uint32) uint32 {
	return (x & y) ^ (x & z) ^ (y & z)
}

// E0256 is the Upper Sigma 0 function for SHA-256
func E0256(x uint32) uint32 {
	return bits.RotateLeft32(x, -2) ^
		bits.RotateLeft32(x, -13) ^
		bits.RotateLeft32(x, -22)
}

// E1256 is the Upper Sigma 1 function for SHA-256
func E1256(x uint32) uint32 {
	return bits.RotateLeft32(x, -6) ^
		bits.RotateLeft32(x, -11) ^
		bits.RotateLeft32(x, -25)
}

// S0256 is the Lower Sigma 1 function for SHA-256
func S0256(x uint32) uint32 {
	return bits.RotateLeft32(x, -7) ^
		bits.RotateLeft32(x, -18) ^
		x >> 3
}

// S1256 is the Lower Sigma 1 function for SHA-256
func S1256(x uint32) uint32 {
	return bits.RotateLeft32(x, -17) ^
		bits.RotateLeft32(x, -19) ^
		x >> 10
}

// Padding message to length multiple of 512
func Padding(m []byte) []byte {
	var s []byte
	bytes := len(m) // length in bytes
	l := 8 * bytes  // length in bits
	//n0 :=
	p := (l + 1) / 512         // p * 512 = (l+1) - remainder (remainder < 512)
	k := p*512 + 448 - (l + 1) // p * 512 + 448 = (l+1) + k (l+1+k = 448mod512)
	kbytes := (k+1) / 8

	if (k+1) % 8 != 0 {
		panic("Error: Some length problem with padding")
	}

	pad := make([]byte, kbytes) // padding full of zeros and desired length

    pad[0] = 1 << 7  // set first byte in padding to start with 1

    lbytes := make([]byte, 8)
    lb := uint64(l)
    binary.BigEndian.PutUint64(lbytes, lb)

    s = append(m, pad...) // 1 followed by k zeros
    s = append(s, lbytes...)

    // fmt.Printf("Message: %s\nPadded message: %x\n", m, s)
	return s
}

// Parsing32 padded message s into blocks of m=512 length with 16 words.
func Parsing32(s []byte) [][16]uint32{
    m := 512
    intlen := m / 16
    nb :=  intlen / 8 // number of bytes per word. = 4 for SHA-256

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
func PrepareSchedule(m [16]uint32) [64]uint32{
    var w [64]uint32

    copy(w[0:16], m[0:16])

    for t := 16; t < 64; t++ {
        w[t] = S1256(w[t-2]) + w[t-7] + S0256(w[t-15]) + w[t-16]
    }
    return w
}

// HashComputation computes one iteration (one block)
func HashComputation(w [64]uint32, hash [8]uint32) [8]uint32{
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

    for t :=0; t < 64; t++ {

        t1 := h + E1256(e) + Ch(e, f, g) + kconst[t] + w[t]
        t2 := E0256(a) + Maj(a, b, c)
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

// Sha256 returns SHA-256 hash of message
func Sha256(message []byte) [8]uint32 {
    s := Padding(message)
    p := Parsing32(s)

    // initialize hash
    hash := InitialHash()


    for i := 1; i <= len(p); i++ {
        w := PrepareSchedule(p[i-1])

        hash = HashComputation(w, hash)
    }

    // hashed := make([]byte, 8*4)

    // for i, h := range hash {
    //     binary.BigEndian.PutUint32(hashed[4*i:], h)
    // }


    return hash// hashed
}
