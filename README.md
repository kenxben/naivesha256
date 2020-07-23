# Secure Hash Algorithm SHA-256 (naive) implementation

Exercise implementation of SHA-256 algorithm. This package is for **educational purposes only** and is not recommended for use in production. For example, it has not been tested for big strings, nor any edge cases.
The code in this implementation is intended to be more 'human readable' than other (probably) more efficient implementations.

## Usage

Install the package:

```
$ go get -u github.com/kenxben/naivesha256
```

Use it in a main.go:
```
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
```
Run in terminal with a message to hash:
```
$ go run main.go --message "abc"
[ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad]

```
The hash value is an array of 8 uint32 printed in hexadecimal.

## Algorithm outline

The complete algorithm specifications can be found [here](http://dx.doi.org/10.6028/NIST.FIPS.180-4).

The input message length *l* in bits can be any number from 0 to 2^64. The message is transformed following these steps:
1. Preprocessing
    1. Padding the message to a multiple of 512 bits
    2. Parsing the message into blocks of 512 bits (or 16 uint32)
    3. Initialize hash values (8 uint32 values specific to the algorithm)
2. Hash computation. For each block (i)
    1. Compute a "schedule" from the last hash value
    2. Update the hash value by applying a set of computations on the last hash value and "schedule"
The hash value computed for the last block is the final message digest.

## Test cases

Some test cases from [here](https://www.di-mgt.com.au/sha_testvectors.html)

input message | output
--- | ---
"abc" | ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
"" | e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855
"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" | 248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1


## Licence
MIT
