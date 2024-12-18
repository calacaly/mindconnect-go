SECRETS_PATH=./secrets

run:
	go run main.go

genapi:
	bash ./scripts/openapi.sh

genkey:
	mkdir -p ${SECRETS_PATH}
	openssl genrsa -out ${SECRETS_PATH}/private.pem 3072
	openssl rsa -in ${SECRETS_PATH}/private.pem -pubout -out ${SECRETS_PATH}/public.pem
	chmod 600 -R ${SECRETS_PATH}
test:
	go test ./... -v

debug:
	rm -rf mindconnect-go
	go build -gcflags "-N -l" -o mindconnect-go main.go
	gdb mindconnect-go

.PHONY: run genapi test debug