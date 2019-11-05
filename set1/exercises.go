package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/bits"
	"os"
	"sort"
)

func main() {
	charFrequency := charFreqInText()

	fmt.Println("exercise 1: ")
	ex1([]byte("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))

	fmt.Println("exercise 2: ")
	ex2(bytes.NewBufferString("1c0111001f010100061a024b53535009181c"), bytes.NewBufferString("686974207468652062756c6c277320657965"))

	fmt.Println("exercise 3: ")
	ex3([]byte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"), charFrequency)

	fmt.Println("exercise 4: ")
	ex4(charFrequency)

	fmt.Println("exercise 5: ")
	ex5([]byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"))
	// Below yields 37
	// fmt.Println(hammingDistance([]byte("this is a test"), []byte("wokka wokka!!!")))

	fmt.Println("exercise 6: ")
	ex6(charFrequency)

	fmt.Println("exercise 7: ")
	ex7()

	fmt.Println("exercise 8: ")
	ex8()

}

func charFreqInText() map[byte]int {
	file, err := os.Open("book.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	r := bufio.NewReader(file)
	m := make(map[byte]int)
	for {
		b, _, err := r.ReadLine()
		if err != nil {
			break
		}
		for _, x := range b {
			m[x]++
		}
	}
	return m
}

// Convert hex to base64
func ex1(s []byte) {
	decoded := decodeHex(s)
	fmt.Printf("%s\n", encodeBase64(decoded))
}

func encodeBase64(s []byte) []byte {
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(s)))
	base64.StdEncoding.Encode(dst, s)
	return dst
}

func decodeBase64(s []byte) []byte {
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(s)))
	n, err := base64.StdEncoding.Decode(dst, s)
	if err != nil {
		log.Fatal(err)
	}
	return dst[:n]
}

func encodeHex(s []byte) []byte {
	dst := make([]byte, hex.EncodedLen(len(s)))
	hex.Encode(dst, s)
	return dst
}

func decodeHex(s []byte) []byte {
	dst := make([]byte, hex.DecodedLen(len(s)))
	n, err := hex.Decode(dst, s)
	if err != nil {
		log.Fatal(err)
	}
	return dst[:n]
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
func ex3(e []byte, charFreq map[byte]int) {
	decoded := decodeHex(e)
	decrypted := decrypt(decoded, charFreq)
	fmt.Printf("decrypted: %s, key: %x\n", decrypted.b, decrypted.key)
}

type decryptedBytes struct {
	b     []byte
	score float64
	key   byte
}

func decrypt(b []byte, charFreq map[byte]int) decryptedBytes {
	var best decryptedBytes
	for i := 0; i < 256; i++ {
		dec := make([]byte, len(b))
		for j := 0; j < len(dec); j++ {
			dec[j] = b[j] ^ byte(i)
		}
		s := frequencyAnalysisScore(dec, charFreq)
		if s > best.score {
			best = decryptedBytes{dec, s, byte(i)}
		}
	}
	return best
}

// Detect single-character XOR
func ex4(charFreq map[byte]int) {
	file, err := os.Open("ex4.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	r := bufio.NewReader(file)
	var best decryptedBytes
	for {
		b, _, err := r.ReadLine()
		if err != nil {
			break
		}
		decrypted := decrypt(decodeHex(b), charFreq)
		if decrypted.score > best.score {
			best = decrypted
		}
	}
	fmt.Printf("decrypted: %s score: %v, key: %x\n", best.b, best.score, best.key)
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

func frequencyAnalysisScore(str []byte, charFreq map[byte]int) float64 {
	score := 0
	for _, b := range str {
		score += charFreq[b]
	}
	return float64(score) / float64(len(str))
}

// Repeating-key XOR
func ex5(s []byte) {
	fmt.Printf("encrypted: %s\n", encrypt(s, []byte("ICE")))
}

// encrypts a byte slice with the provided key and
// returns the hex encoded result.
func encrypt(s []byte, key []byte) []byte {
	encrypted := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		encrypted[i] = s[i] ^ key[i%len(key)]
	}
	encoded := make([]byte, hex.EncodedLen(len(encrypted)))
	hex.Encode(encoded, encrypted)
	return encoded
}

// Break repeating-key XOR
func ex6(charFreq map[byte]int) {
	fileBytes, err := ioutil.ReadFile("ex6.txt")
	if err != nil {
		log.Fatal(err)
	}
	encrypted := decodeBase64(fileBytes)
	keyLen := estimateKeyLen(encrypted)

	var (
		key       = make([]byte, keyLen)
		decrypted = make([]byte, len(encrypted))
		blocks    [][]byte
	)

	i := 0
	for {
		if i > len(encrypted)-keyLen {
			// blocks = append(blocks, encrypted[i:len(encrypted)])
			break
		}
		blocks = append(blocks, encrypted[i:i+keyLen])
		i += keyLen
	}

	for k := 0; k < keyLen; k++ {
		var transposedBlock []byte
		for i := 0; i < len(blocks); i++ {
			transposedBlock = append(transposedBlock, blocks[i][k])
		}
		// fmt.Printf("%q\n", transposedBlock)
		d := decrypt(transposedBlock, charFreq)
		fmt.Printf("%q\n", d.b)
		key[k] = d.key
	}
	fmt.Printf("key: %q, decrypted: %s\n", key, decrypted)
}

func estimateKeyLen(b []byte) int {
	var (
		likeliestKeyLen   int
		lowestHammingDist = math.MaxFloat64
		maxKeyLen         = 40
		n                 = 10 // how many keyLen blocks to calculate the hamming distance
	)
	for keyLen := 2; keyLen <= maxKeyLen; keyLen++ {
		totalDist := 0
		for i := 0; i < n*2; i = i + 2 {
			first := b[keyLen*i : keyLen*(i+1)]
			second := b[keyLen*(i+1) : keyLen*(i+2)]
			totalDist += hammingDistance(first, second)
		}
		normalized := float64(totalDist) / float64(n) / float64(keyLen)
		// fmt.Printf("distance for key %v: %v\n", keyLen, normalized)
		if normalized < lowestHammingDist {
			lowestHammingDist = normalized
			likeliestKeyLen = keyLen
		}
	}
	return likeliestKeyLen
}

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

}

func ex8() {}
