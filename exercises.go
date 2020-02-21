package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"sort"
)

var (
	set1 = flag.Bool("set1", false, "whether to run the exercises in set 1")
	set2 = flag.Bool("set2", false, "whether to run the exercises in set 2")
)

func charFreqInText() map[byte]int {
	file, err := os.Open("testdata/book.txt")
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
	n := hex.Encode(dst, s)
	if n != hex.EncodedLen(len(s)) {
		log.Fatal("issue with hex encoding")
	}
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
	file, err := os.Open("testdata/ex4.txt")
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
	fileBytes, err := ioutil.ReadFile("testdata/ex6.txt")
	if err != nil {
		log.Fatal(err)
	}
	encrypted := decodeBase64(fileBytes)
	// Step 1 - find the key length by trying some values
	smallest := math.MaxFloat64
	smallestKeyLen := 0
	for i := 2; i < 40; i++ {
		// Step 3 - take 10 keysize blocks and calculate normalized edit distance
		dist := 0
		for n := 0; n < 10; n++ {
			a := encrypted[n*i : n*i+i]
			b := encrypted[n*i+i : n*i+i*2]
			dist += hammingDistance(a, b)
		}
		normalized := float64(dist / i)
		if normalized < smallest {
			smallest = normalized
			smallestKeyLen = i
		}
	}

	// Step 4 - whichever keyLen has the lowest edit distance is probably the key
	keyLen := smallestKeyLen

	// Step 5 - break into keyLen blocks
	var blocks [][]byte
	i := 0
	for {
		if i > len(encrypted)-keyLen {
			break
		}
		blocks = append(blocks, encrypted[i:i+keyLen])
		i += keyLen
	}

	// Step 6 - transpose blocks
	key := make([]byte, keyLen)
	keyScore := 0.0
	for k := 0; k < keyLen; k++ {
		var transposedBlock []byte
		for i := 0; i < len(blocks); i++ {
			transposedBlock = append(transposedBlock, blocks[i][k])
		}
		// Step 7 - solve for one key character
		d := decrypt(transposedBlock, charFreq)
		// Step 8 - add the single byte XOR key to the final key
		keyScore += d.score
		key[k] = d.key
	}

	// Do the decryption
	var decrypted = make([]byte, len(encrypted))
	for i, b := range encrypted {
		decrypted[i] = b ^ key[i%len(key)]
	}

	fmt.Printf("key: %q, decrypted: %s\n", key, decrypted)
}

func hammingDistance(a, b []byte) int { // Step 2 of Set 1 Exercise 6
	if len(a) != len(b) {
		log.Fatal("byte slices must be of equal length to calculate Hamming distance")
	}
	var dist int
	for _, x := range xor(a, b) {
		for i := 0; i < 8; i++ {
			if x&(1<<i) > 0 {
				dist++
			}
		}
	}
	return dist
}

// AES in ECB mode
func ex7() {
	// 128 bytes
	cipherKey := []byte("YELLOW SUBMARINE")
	fileBytes, err := ioutil.ReadFile("testdata/ex7.txt")
	if err != nil {
		log.Fatal(err)
	}
	decoded := decodeBase64(fileBytes)
	fmt.Printf("%s\n", aesecbDecrypt(decoded, cipherKey))
}

func aesecbDecrypt(text, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	var decrypted []byte
	for i := 0; i < len(text); i = i + aes.BlockSize {
		dst := make([]byte, aes.BlockSize)
		block.Decrypt(dst, text[i:i+aes.BlockSize])
		decrypted = append(decrypted, dst...)
	}
	return decrypted
}

// Detect AES in ECB mode
func ex8() {
	file, err := os.Open("testdata/ex8.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	r := bufio.NewReader(file)
	var bestText []byte
	var best int
	for {
		b, _, err := r.ReadLine()
		if err != nil {
			break
		}
		m := make(map[[aes.BlockSize]byte]int)
		tmpTotal := 0
		for i := 0; i < len(b); i = i + 16 {
			var tmp [16]byte
			copy(tmp[:], b[i:i+aes.BlockSize])
			m[tmp]++
			if m[tmp] > 1 {
				tmpTotal++
			}
		}
		if tmpTotal > best {
			best = tmpTotal
			bestText = b
		}
	}
	fmt.Printf("%s", bestText)
}

func ex9() {
	x := []byte("YELLOW SUBMARINE")
	size := 30
	fmt.Printf("%q\n", pkcs7Pad(x, size))
}

func pkcs7Pad(b []byte, size int) []byte {
	padding := size - len(b)
	for i := 0; i < padding; i++ {
		b = append(b, byte(padding))
	}
	return b
}

func ex10() {
	key := []byte("YELLOW SUBMARINE")
	encoded, err := ioutil.ReadFile("testdata/ex10.txt")
	if err != nil {
		log.Fatal(err)
	}
	cipherText := decodeBase64(encoded)
	if len(cipherText)%aes.BlockSize != 0 {
		log.Fatal("cipherText is not a multiple of the block size")
	}
	iv := make([]byte, aes.BlockSize)
	for i := 0; i < aes.BlockSize; i++ {
		iv[i] = byte(0)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	//fmt.Printf("%s\n", cbcDecryptStdLib(block, cipherText, iv))
	fmt.Printf("%s\n", cbcDecrypt(block, cipherText, iv))
}

func cbcDecrypt(block cipher.Block, cipherText, iv []byte) []byte {
	var decrypted []byte
	prev := iv // The first plaintext block is XOR'd with the IV.
	for i := 0; i < len(cipherText); i = i + aes.BlockSize {
		cur := cipherText[i : i+aes.BlockSize]
		dst := make([]byte, aes.BlockSize)
		block.Decrypt(dst, cur)
		decrypted = append(decrypted, xor(prev, dst)...)
		prev = cur
	}
	return decrypted
}

func cbcDecryptStdLib(block cipher.Block, cipherText, iv []byte) []byte {
	// Using the standard library
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)
	return cipherText
}

func ex11() {}

func ex12() {}

func ex13() {}

func ex14() {}

func ex15() {}

func ex16() {}

func main() {
	flag.Parse()
	charFrequency := charFreqInText()

	if *set1 {
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

	if *set2 {
		fmt.Println("exercise 9: ")
		ex9()
		fmt.Println("exercise 10: ")
		ex10()
		fmt.Println("exercise 11: ")
		ex11()
		fmt.Println("exercise 12: ")
		ex12()
		fmt.Println("exercise 13: ")
		ex13()
		fmt.Println("exercise 14: ")
		ex14()
		fmt.Println("exercise 15: ")
		ex15()
		fmt.Println("exercise 16: ")
		ex16()
	}
}
