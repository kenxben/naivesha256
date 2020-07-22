package naivesha256

import (
	"fmt"
	"testing"
)

// Ch function of SHA-256
func TestCh(t *testing.T) {
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
		testname := fmt.Sprintf("Ch(%b, %b, %b)", tt.x, tt.y, tt.z)
		t.Run(testname, func(t *testing.T) {
			resp := Ch(tt.x, tt.y, tt.z)
			if resp != tt.r {
				t.Errorf("got %b, expected %b", resp, tt.r)
			}
		})
	}
}

// Ch function of SHA-256
func TestMaj(t *testing.T) {
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
		testname := fmt.Sprintf("Maj(%b, %b, %b)", tt.x, tt.y, tt.z)
		t.Run(testname, func(t *testing.T) {
			resp := Maj(tt.x, tt.y, tt.z)
			if resp != tt.r {
				t.Errorf("got %b, expected %b", resp, tt.r)
			}
		})
	}
}
