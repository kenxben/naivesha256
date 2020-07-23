package naivesha256

import (
	"fmt"
	"reflect"
	"testing"
)

// Test for intermediate steps
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf

func TestChoose(t *testing.T) {
	var tests = []struct {
		x, y, z uint32
		r       uint32
	}{
		{0b0000, 0b0000, 0b0000, 0b0000},
		{0b0001, 0b0000, 0b0001, 0b0000},
		{0b0000, 0b0000, 0b0001, 0b0001},
		{0b1001, 0b1100, 0b0001, 0b1000},
	}

	for _, tt := range tests {
		testname := fmt.Sprintf("choose(%b, %b, %b)", tt.x, tt.y, tt.z)
		t.Run(testname, func(t *testing.T) {
			resp := choose(tt.x, tt.y, tt.z)
			if resp != tt.r {
				t.Errorf("got %b, expected %b", resp, tt.r)
			}
		})
	}
}

func TestMajority(t *testing.T) {
	var tests = []struct {
		x, y, z uint32
		r       uint32
	}{
		{0b0000, 0b0000, 0b0000, 0b0000},
		{0b0001, 0b0000, 0b0001, 0b0001},
		{0b0000, 0b0000, 0b0001, 0b0000},
		{0b1001, 0b1100, 0b0001, 0b1001},
	}

	for _, tt := range tests {
		testname := fmt.Sprintf("majority(%b, %b, %b)", tt.x, tt.y, tt.z)
		t.Run(testname, func(t *testing.T) {
			resp := majority(tt.x, tt.y, tt.z)
			if resp != tt.r {
				t.Errorf("got %b, expected %b", resp, tt.r)
			}
		})
	}
}

func TestPadding(t *testing.T) {
	for _, tt := range paddingtests {
		testname := fmt.Sprintf("padding(%b)", tt.in)
		t.Run(testname, func(t *testing.T) {
			resp := padding(tt.in)
			if !reflect.DeepEqual(resp, tt.out) {
				t.Errorf("got %b, expected %b", resp, tt.out)
			}
		})
	}
}

func TestParsing(t *testing.T) {
	s := []byte{
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	}
	want := [][16]uint32{
		[16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
	r := parsing(s)
	if !reflect.DeepEqual(want, r) {
		t.Errorf("Parsing(%v) failed. got %v, expected %v", s, r, want)
	}
}

func TestNewHash(t *testing.T) {
	var tests = []struct {
		m []byte
		h Hash
	}{
		{[]byte(""), Hash{[]byte("")}},
		{[]byte("abc"), Hash{[]byte("abc")}},
	}
	for _, tt := range tests {
		testname := fmt.Sprintf("NewHash(%s)", tt.m)
		t.Run(testname, func(t *testing.T) {
			resp := NewHash(tt.m)
			if !reflect.DeepEqual(resp, tt.h) {
				t.Errorf("got %#v, expected %#v", resp, tt.h)
			}
		})
	}
}

func TestHash(t *testing.T) {
	for _, tt := range hashtests {
		testname := fmt.Sprintf("Hash.Hash(%s)", tt.input)
		h := NewHash(tt.input)
		t.Run(testname, func(t *testing.T) {
			resp := h.Hash()
			if !reflect.DeepEqual(resp, tt.hash) {
				t.Errorf("\ngot      %#x, \nexpected %#x", resp, tt.hash)
			}
		})
	}
}
