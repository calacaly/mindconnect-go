package store

import (
	"crypto/rsa"
	"errors"
	"os"

	"github.com/calacaly/mindconnect-go/internal/api/agentmanagement/v3/models"
	"github.com/calacaly/mindconnect-go/internal/utils"
)

const (
	ConfigurationType = iota
	ClientIdentifierType
	AccessTokenType
	OauthPublicKeyType
	PrivateKeyType
	PublicKeyType
)

const (
	OnBoardFile          = "onboard.json"
	ClientIdentifierFile = "client.json"
	OauthPublicKeyFile   = "oauth_public_key.json"
	PrivateKeyFile       = "private.pem"
	PublicKeyFile        = "public.pem"
)

type LocalStorage struct {
	basePath string
}

type StorageClass interface {
	GetConfig(interface{}) error
	Save([]byte, int) error
}

// NewLocalStorage creates a new LocalStorage object with the given base path.
//
// The method returns the newly created LocalStorage object.
func NewLocalStorage(basePath string) StorageClass {
	return &LocalStorage{
		basePath: basePath,
	}
}

// GetConfig reads a file associated with the given config interface{} and
// decodes its content into the config interface{}. The method returns an error
// if the file could not be read or the content could not be decoded.
//
// The method requires the basePath to be set.
//
// The method supports the following config interfaces{}:
//
// *models.ClientIdentifier
// *models.Configuration
// *models.TokenKey
// *rsa.PrivateKey
// *rsa.PublicKey
//
// For any other config interface{}, an error is returned.
func (l LocalStorage) GetConfig(config interface{}) error {
	var path string

	switch cfg := config.(type) {
	case *models.ClientIdentifier:
		path = l.basePath + "/" + ClientIdentifierFile
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		err = cfg.UnmarshalBinary(data)
		if err != nil {
			return err
		}
	case *models.Configuration:
		path = l.basePath + "/" + OnBoardFile
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		err = cfg.UnmarshalBinary(data)
		if err != nil {
			return err
		}
	case *models.TokenKey:
		path = l.basePath + "/" + OauthPublicKeyFile
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		err = cfg.UnmarshalBinary(data)
		if err != nil {
			return err
		}
	case *rsa.PrivateKey:
		path = l.basePath + "/" + PrivateKeyFile
		data, err := utils.PrivateKeyFromPemFile(path)
		if err != nil {
			return err
		}
		*cfg = *data
	case *rsa.PublicKey:
		path = l.basePath + "/" + PublicKeyFile
		data, err := utils.PublicKeyFromPemFile(path)
		if err != nil {
			return err
		}
		*cfg = *data
	default:
		return errors.New("unsupported config type")
	}

	return nil
}

// Save writes the given data to the local storage file
// that is associated with the given configType.
//
// The method returns an error if the file could not be written.
//
// The method requires the basePath to be set.
func (l LocalStorage) Save(data []byte, configType int) error {

	var path string
	switch configType {
	case ConfigurationType:
		path = l.basePath + "/" + OnBoardFile
	case ClientIdentifierType:
		path = l.basePath + "/" + ClientIdentifierFile
	case OauthPublicKeyType:
		path = l.basePath + "/" + OauthPublicKeyFile
	case PrivateKeyType:
		path = l.basePath + "/" + PrivateKeyFile
	case PublicKeyType:
		path = l.basePath + "/" + PublicKeyFile
	default:
		return errors.New("unsupported config type")
	}

	err := os.WriteFile(path, data, 0600)
	if err != nil {
		return err
	}
	return nil
}
