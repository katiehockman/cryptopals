package main

import (
	"fmt"
)

func main() {
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

func ex9() {
	padded := []byte("YELLOW SUBMARINE")
	b := byte(20 - len(padded))
	for i := len(padded); i < 20; i++ {
		padded = append(padded, b)
	}
	fmt.Printf("%q\n", padded)
}

func ex10() {}

func ex11() {}

func ex12() {}

func ex13() {}

func ex14() {}

func ex15() {}

func ex16() {}
