default: help

all: win mac lin

win:
	# Windows x64
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" dnschecker.go

mac:
	# Mac, Apple Silicon
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o dnschecker.mac-arm64 dnschecker.go 
	
lin: 
	# Linux x64
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dnschecker.linux-x64 dnschecker.go
	# For ARM64 Linux
	#GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o dnschecker.linux-arm64 dnschecker.go

build: 
	go build

zip: 
	# Get the current date in YYYYMMDD format
	DATE=$$(date +%Y%m%d); \
	zip -r dnschecker_$${DATE}.zip dnschecker.exe dnschecker.mac* dnschecker.linux* dnschecker.bat dnschecker.command README.md

clean: 
	go clean
	rm -f dnschecker
	rm -f dnschecker.exe
	rm -f dnschecker.mac*
	rm -f dnschecker.linux*

help:
	@echo "$${message}"

define message 
Usage:
	make <target> 

List of targets
	win        : build for Windows/x64
	mac        : build for Mac/arm64
	lin        : build for Linux/x64
	build      : build for local machine
	all        : build for windows, mac, and linux

Example
	make mac  
    -> it'll build binary for macOS

endef
export message



