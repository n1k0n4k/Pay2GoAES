// Reads a raw binary file and 32-byte AES key and returns an AES encrypted byte array in golang format.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strconv"
)

const (
	KeyFlag     uint = 0
	PayloadFlag uint = 1
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func encryptAES(plaintext []byte, key []byte) (ciphertext []byte) {
	c, err := aes.NewCipher(key)
	check(err)
	gcm, err := cipher.NewGCM(c)
	check(err)

	nonce := make([]byte, gcm.NonceSize())

	_, err = io.ReadFull(rand.Reader, nonce)
	check(err)

	ciphertext = gcm.Seal(nonce, nonce, plaintext, nil)
	return
}

func fPrintPay(seal []byte, flag uint) {

	form := "0x%s"
	end := ", "
	if flag == PayloadFlag {
		fmt.Println("")
		fmt.Println("[!] AES Encrypted Payload Array:")
		fmt.Println("")
		fmt.Print("buf := []byte { ")
	} else if flag == KeyFlag {
		fmt.Println("")
		fmt.Println("[!] AES Key Array")
		fmt.Println("")
		fmt.Print("key := []byte { ")
	}
	for i, s := range seal {
		if i == (len(seal) - 1) {
			end = ""
		}
		fmt.Print(fmt.Sprintf(form, strconv.FormatInt(int64(s), 16)) + end)
	}

	fmt.Print(" } \n\n")

}

func main() {
	var eKey []byte
	fmt.Println("Golang AES Payload Encryption v0.01")
	args := os.Args[1:]

	if len(args) == 0 {
		fmt.Printf("Usage: %s ~/payload.bin <OPTIONAL32BYTEKEY>", os.Args[0])
		os.Exit(0)
	} else if len(args) == 1 {
		eKey = make([]byte, 32)
		_, err := rand.Read(eKey)
		check(err)
	} else if len(args) == 2 {
		eKey = []byte(args[1])
		if len(eKey) != 32 {
			panic("error: key is not 32 bytes")
		}
	} else {
		panic("error: incorrect number of arguments")
	}

	fPath := args[0]

	binFile, err := os.ReadFile(fPath)
	check(err)

	ciphertext := encryptAES(binFile, eKey)

	fPrintPay(eKey, KeyFlag)
	fPrintPay(ciphertext, PayloadFlag)

}
