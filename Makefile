run:
	go run main.go

genapi:
	bash ./scripts/openapi.sh

test:
	go test ./...

.PHONY: run genapi test