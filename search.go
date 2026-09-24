package keycheck

import (
	"math/bits"
	"strings"
)

const (
	lowBits  = 0x0101010101010101
	highBits = 0x8080808080808080
)

var byteRank = [256]uint8{
	// Background byte-frequency ranks from the memchr crate's default_rank.rs
	// (Andrew Gallant, Unlicense OR MIT). A lower rank predicts a rarer byte.
	55, 52, 51, 50, 49, 48, 47, 46, 45, 103, 242, 66, 67, 229, 44, 43,
	42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 56, 32, 31, 30, 29, 28,
	255, 148, 164, 149, 136, 160, 155, 173, 221, 222, 134, 122, 232, 202, 215, 224,
	208, 220, 204, 187, 183, 179, 177, 168, 178, 200, 226, 195, 154, 184, 174, 126,
	120, 191, 157, 194, 170, 189, 162, 161, 150, 193, 142, 137, 171, 176, 185, 167,
	186, 112, 175, 192, 188, 156, 140, 143, 123, 133, 128, 147, 138, 146, 114, 223,
	151, 249, 216, 238, 236, 253, 227, 218, 230, 247, 135, 180, 241, 233, 246, 244,
	231, 139, 245, 243, 251, 235, 201, 196, 240, 214, 152, 182, 205, 181, 127, 27,
	212, 211, 210, 213, 228, 197, 169, 159, 131, 172, 105, 80, 98, 96, 97, 81,
	207, 145, 116, 115, 144, 130, 153, 121, 107, 132, 109, 110, 124, 111, 82, 108,
	118, 141, 113, 129, 119, 125, 165, 117, 92, 106, 83, 72, 99, 93, 65, 79,
	166, 237, 163, 199, 190, 225, 209, 203, 198, 217, 219, 206, 234, 248, 158, 239,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
}

type exactLiteral struct {
	needle string
	rare   int
}

func newExactLiteral(needle string) exactLiteral {
	var rare int
	for i := 1; i < len(needle); i++ {
		if byteRank[needle[i]] < byteRank[needle[rare]] {
			rare = i
		}
	}
	return exactLiteral{needle: needle, rare: rare}
}

func (l exactLiteral) index(s string) int {
	needle := l.needle
	n := len(needle)
	switch {
	case n == 0:
		return 0
	case n == 1:
		return strings.IndexByte(s, needle[0])
	case n >= len(s):
		if s == needle {
			return 0
		}
		return -1
	}
	// Vectorized IndexByte skips quickly to the predicted rarest byte.
	// Frequent false candidates switch to a word-at-a-time scan whose cost does not depend on byte frequency.
	last := len(s) - n
	first, final := needle[0], needle[n-1]
	var fails int
	for i := 0; i <= last; {
		o := strings.IndexByte(s[i+l.rare:last+l.rare+1], needle[l.rare])
		if o < 0 {
			return -1
		}
		i += o
		if s[i] == first && s[i+n-1] == final && s[i:i+n] == needle {
			return i
		}
		i++
		fails++
		if overBudget(fails, n, i, 5) {
			return l.indexWords(s, i)
		}
	}
	return -1
}

func (l exactLiteral) indexWords(s string, i int) int {
	needle := l.needle
	n := len(needle)
	last := len(s) - n
	first, final := needle[0], needle[n-1]
	firsts, finals := lowBits*uint64(first), lowBits*uint64(final)
	tails := s[n-1:]
	start := i
	var fails int
	for ; i+8 <= last+1; i += 8 {
		z := (loadWord(s[i:i+8]) ^ firsts) | (loadWord(tails[i:i+8]) ^ finals)
		m := (z - lowBits) &^ z & highBits
		if m == 0 {
			continue
		}
		for ; m != 0; m &= m - 1 {
			j := i + bits.TrailingZeros64(m)>>3
			if s[j:j+n] == needle {
				return j
			}
			fails++
		}
		if overBudget(fails, n, i-start, 3) {
			if j := strings.Index(s[i+8:], needle); j >= 0 {
				return i + 8 + j
			}
			return -1
		}
	}
	for ; i <= last; i++ {
		if s[i] == first && s[i+n-1] == final && s[i:i+n] == needle {
			return i
		}
	}
	return -1
}

func loadWord(s string) uint64 {
	_ = s[7]
	return uint64(s[0]) | uint64(s[1])<<8 | uint64(s[2])<<16 | uint64(s[3])<<24 |
		uint64(s[4])<<32 | uint64(s[5])<<40 | uint64(s[6])<<48 | uint64(s[7])<<56
}

func overBudget(fails, size, scanned, shift int) bool {
	return fails*(1+size>>shift) > 4+scanned>>shift
}
