#!/usr/bin/zsh
INDEX=0
for file in pay2build/temp*.LOADED.go ; do \
    echo "Building $file to payload $index."
    env GOOS=windows GOARCH=amd64 go build -ldflags='-w -s' -o pay2build/payload$INDEX.exe file ; \
    upx --brute pay2build/payload$INDEX.exe ; $INDEX++ ; done;