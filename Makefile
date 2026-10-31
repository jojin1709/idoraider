.PHONY: build build-windows test clean

build:
	go build -o idoraider ./cmd/idoraider

build-windows:
	go build -o idoraider.exe ./cmd/idoraider

test:
	go test -v ./...

clean:
	rm -f idoraider idoraider.exe

