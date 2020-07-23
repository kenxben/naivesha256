package naivesha256

// Intermediate test vectors
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf

// Test vectors
// https://www.di-mgt.com.au/sha_testvectors.html
var hashtests = []struct {
	input []byte
	hash  [8]uint32
}{
	{
		[]byte("abc"),
		[8]uint32{
			0xba7816bf,
			0x8f01cfea,
			0x414140de,
			0x5dae2223,
			0xb00361a3,
			0x96177a9c,
			0xb410ff61,
			0xf20015ad,
		},
	},
	{
		[]byte(""),
		[8]uint32{
			0xe3b0c442,
			0x98fc1c14,
			0x9afbf4c8,
			0x996fb924,
			0x27ae41e4,
			0x649b934c,
			0xa495991b,
			0x7852b855,
		},
	},
	{
		[]byte("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
		[8]uint32{
			0xcf5b16a7,
			0x78af8380,
			0x036ce59e,
			0x7b049237,
			0x0b249b11,
			0xe8f07a51,
			0xafac4503,
			0x7afee9d1,
		},
	},
}

// "abc" padding according to specs document
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
var paddingtests = []struct {
	in  []byte
	out []byte
}{
	{
		[]byte("abc"),
		[]byte{
			0b01100001,
			0b01100010,
			0b01100011,
			0b10000000,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0b00000000,
			0b00000000,
			0b00000000,
			0b00011000,
		},
	},
}
