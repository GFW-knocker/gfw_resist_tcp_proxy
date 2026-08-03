# gfk build targets. GUI needs cgo + mingw-w64; CLI is cgo-free.
.PHONY: all cli-linux cli-windows gui test clean

all: cli-linux cli-windows

cli-linux:
	CGO_ENABLED=0 GOOS=linux go build -o dist/gfk ./cmd/gfk

cli-windows:
	CGO_ENABLED=0 GOOS=windows go build -o dist/gfk.exe ./cmd/gfk

gui:
	CGO_ENABLED=1 go build -tags gui -o dist/gfk-gui.exe ./cmd/gfk-gui

test:
	go test ./...

clean:
	rm -rf dist
