# pay2GoAES

A simple binary payload AES encryption/conversion tool for use with GoLang shellcode runners.

## Usage

- Takes a single argument that is a path to a beacon.bin or any shellcode file 
- Creates random AES key and encrypts payload
- Format prints the key and encrypted payload in GoLang byte array format for easy copy paste
- Optional second argument for a custom 32 byte key

# pay2GoAESfile

## Usage
- Takes a single argument that is a path to a beacon.bin or any shellcode file 
- Creates random AES key and encrypts payload
- Searches pwd for files with "temp*.go" pattern
- Replaces \<PAYLOAD\> and \<KEY\> keywords in temp files with format printed golang 
- Saves new copy of file ready to build
- Optional second argument for a custom 32 byte key
