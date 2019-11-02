package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"math/bits"
	"os"
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

	fmt.Println("exercise 4: ")
	ex4()

	fmt.Println("exercise 5: ")
	ex5([]byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"))

	fmt.Println("exercise 6: ")
	ex6()
	hammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))

	fmt.Println("exercise 7: ")
	ex7()

	fmt.Println("exercise 8: ")
	ex8()

}

// Convert hex to base64
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

// Fixed XOR
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

// Single-byte XOR cipher
func ex3(e []byte) {
	decrypted := decryptEncoded(e)
	fmt.Printf("decrypted: %s, key: %x\n", decrypted.b, decrypted.key)
}

type decryptedBytes struct {
	b     []byte
	score int
	key   byte
}

func decryptEncoded(e []byte) decryptedBytes {
	decoded := decodeHex(e)
	var best decryptedBytes
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
	return best
}

// Detect single-character XOR
func ex4() {
	r := fileReader("ex4.txt")
	var best decryptedBytes
	for {
		b, _, err := r.ReadLine()
		if err != nil {
			break
		}
		decrypted := decryptEncoded(b)
		if decrypted.score > best.score {
			best = decrypted
		}
	}
	fmt.Printf("decrypted: %s, score: %d, key: %x\n", best.b, best.score, best.key)
}

func fileReader(filename string) *bufio.Reader {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	return bufio.NewReader(file)
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
		}
	}
	return score
}

// Repeating-key XOR
func ex5(s []byte) {
	key := []byte("ICE")
	encrypted := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		encrypted[i] = s[i] ^ key[i%len(key)]
	}
	encoded := make([]byte, hex.EncodedLen(len(encrypted)))
	hex.Encode(encoded, encrypted)
	fmt.Printf("encrypted: %s\n", encoded)
}

func ex6() {}

func hammingDistance(a, b []byte) int {
	if len(a) != len(b) {
		log.Fatal("byte slices must be of equal length to calculate Hamming distance")
	}
	var dist int
	for _, x := range xor(a, b) {
		// Maybe do this the hard way for learning, but *shrug*
		dist += bits.OnesCount8(x)
	}
	return dist
}

func ex7() {
	r := fileReader("ex6.txt")
	keyLen := bestKeyLen(r)
}

func bestKeyLen(r *bufio.Reader) int {
	var likeliestKeyLen int
	lowestHammingDist := math.MaxInt8
	maxKeyLen := 40
	n := 2
	bytes, err := r.Peek(maxKeyLen * n)
	if err != nil {
		log.Fatal(err)
	}
	for keyLen := 2; keyLen < maxKeyLen; keyLen++ {
		totalDist := 0
		for i := 0; i < n; i++ {
			first := bytes[keyLen*i : keyLen*(i+1)]
			second := bytes[keyLen*(i+1) : keyLen*(i+2)]
			totalDist += hammingDistance(first, second)
		}
		av := totalDist / n
		normalized := av / keyLen
		if normalized < lowestHammingDist {
			lowestHammingDist = normalized
			likeliestKeyLen = keyLen
		}
	}
	return likeliestKeyLen
}

func ex8() {}
