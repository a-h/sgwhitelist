.PHONY: deps clean build

clean: 
	rm -rf ./update/update
	
build:
	GO111MODULE=on GOOS=linux GOARCH=amd64 go build -o update/update ./update
