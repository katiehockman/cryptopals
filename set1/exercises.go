package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"sort"
	"strings"
	"unicode"
)

func main() {
	fmt.Println("exercise 1: ")
	ex1([]byte("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))

	fmt.Println("exercise 2: ")
	ex2(bytes.NewBufferString("1c0111001f010100061a024b53535009181c"), bytes.NewBufferString("686974207468652062756c6c277320657965"))

	fmt.Println("exercise 3: ")
	ex3([]byte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
	// score([]byte("Cooking MC's like a pound of bacon"))

	fmt.Println("exercise 4: ")
	ex4()

	fmt.Println("exercise 5: ")
	ex5()

	fmt.Println("exercise 6: ")
	ex6()

	fmt.Println("exercise 7: ")
	ex7()

	fmt.Println("exercise 8: ")
	ex8()

}

func ex1(s []byte) {
	encoded := base64.StdEncoding.EncodeToString(decodeHex(s))
	fmt.Println(encoded)
}

func decodeHex(b []byte) []byte {
	dst := make([]byte, hex.DecodedLen(len(b)))
	_, err := hex.Decode(dst, b)
	if err != nil {
		log.Fatal(err)
	}
	return dst
}

func ex2(a, b *bytes.Buffer) {
	if a.Len() != b.Len() {
		log.Fatal("buffers must be of equal length")
	}
	aDec, bDec := decodeHex(a.Bytes()), decodeHex(b.Bytes())
	ret := xor(aDec, bDec)
	fmt.Println(hex.EncodeToString(ret))
}

func xor(a, b []byte) []byte {
	ret := make([]byte, len(a))
	for i := 0; i < len(ret); i++ {
		ret[i] = a[i] ^ b[i]
	}
	return ret
}

func ex3(encoded []byte) {
	type decryptedBytes struct {
		b     []byte
		score int
		key   byte
	}
	var best decryptedBytes
	decoded := decodeHex(encoded)
	for i := 0; i < 256; i++ {
		dec := make([]byte, len(decoded))
		for j := 0; j < len(dec); j++ {
			dec[j] = decoded[j] ^ byte(i)
		}
		s := frequencyAnalysisScore(dec)
		if s > best.score {
			best = decryptedBytes{dec, s, byte(i)}
		}
	}
	fmt.Printf("decrypted: %s, key: %x\n", best.b, best.key)
}

type pair struct {
	Key   rune
	Value float64
}
type pairSlice []pair

func (p pairSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p pairSlice) Len() int           { return len(p) }
func (p pairSlice) Less(i, j int) bool { return p[i].Value < p[j].Value }

func sortMapByValue(m map[rune]float64) pairSlice {
	p := make(pairSlice, len(m))
	i := 0
	for k, v := range m {
		p[i] = pair{k, v}
		i++
	}
	sort.Sort(sort.Reverse(p))
	return p
}

func frequencyAnalysisScore(str []byte) int {
	score := 0
	for _, s := range strings.Split(string(str), " ") {
		charFreq := make(map[rune]float64)
		for _, b := range s {
			u := unicode.ToUpper(rune(b))
			if u >= 'A' && u <= 'Z' {
				charFreq[u]++
			}
		}
		sorted := sortMapByValue(charFreq)
		max := 6
		if len(charFreq) < 6 {
			max = len(charFreq)
		}
		for i := 0; i < max; i++ {
			switch sorted[i].Key {
			case 'E', 'T', 'A', 'O', 'I', 'N':
				score++
			}
			switch sorted[len(sorted)-1-i].Key {
			case 'V', 'K', 'J', 'X', 'Q', 'Z':
				score++
			}
		}
	}
	return score
}

func ex4() {}

func ex5() {}

func ex6() {}

func ex7() {}

func ex8() {}
