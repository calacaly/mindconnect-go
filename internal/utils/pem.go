package utils

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
)

var (
	startMarker = "-----BEGIN PUBLIC KEY-----"
	endMarker   = "-----END PUBLIC KEY-----"
)

func PublicKeyLineFromPemFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	key := strings.ReplaceAll(string(data), "\n", "")
	if strings.HasPrefix(key, startMarker) && strings.HasSuffix(key, endMarker) {
		key = strings.TrimSuffix(key, endMarker)
		key = strings.TrimPrefix(key, startMarker)
		return key, nil
	} else {
		return "", errors.New("invalid public key format")
	}

}

func PublicKeyFromPemFile(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)

	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid public key format")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)

	if err != nil {
		return nil, err
	}

	switch k := key.(type) {
	case *rsa.PublicKey:
		return k, nil
	default:
		return nil, errors.New("invalid public key format")
	}
}

func PrivateKeyFromPemFile(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)

	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("invalid private key format")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)

	if err != nil {
		return nil, err
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k, nil
	default:
		return nil, errors.New("invalid private key format")
	}

}

func PublicKeyFromPemString(pubstr string) (*rsa.PublicKey, error) {
	// 检查是否包含开头和结尾的标记
	if !strings.HasPrefix(pubstr, startMarker) || !strings.HasSuffix(pubstr, endMarker) {
		return nil, errors.New("invalid public key format")
	} else {
		pubstr = strings.TrimSuffix(pubstr, endMarker)
		pubstr = strings.TrimPrefix(pubstr, startMarker)
	}

	// 分割字符串，每 64 个字符一行
	var buffer bytes.Buffer
	buffer.WriteString(startMarker + "\n")
	for i := 0; i < len(pubstr); i += 64 {
		end := i + 64
		if end > len(pubstr) {
			end = len(pubstr)
		}
		buffer.WriteString(pubstr[i:end] + "\n")
	}

	buffer.WriteString(endMarker)

	block, _ := pem.Decode(buffer.Bytes())

	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid public key format")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch k := key.(type) {
	case *rsa.PublicKey:
		return k, nil
	default:
		return nil, errors.New("invalid public key format")
	}
}
