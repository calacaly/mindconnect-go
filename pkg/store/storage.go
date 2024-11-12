package store

import (
	"errors"
	"os"

	"github.com/calacaly/mindconnect-go/internal/api/agentmanagement/v3/models"
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
	AccessTokenFile      = "access_token.json"
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

func NewLocalStorage(basePath string) StorageClass {
	return &LocalStorage{
		basePath: basePath,
	}
}

// config *models.xxx
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
	case *models.AccessToken:
		path = l.basePath + "/" + AccessTokenFile
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
	default:
		return errors.New("unsupported config type")
	}

	return nil
}

func (l LocalStorage) Save(data []byte, configType int) error {

	var path string
	switch configType {
	case ConfigurationType:
		path = l.basePath + "/" + OnBoardFile
	case ClientIdentifierType:
		path = l.basePath + "/" + ClientIdentifierFile
	case AccessTokenType:
		path = l.basePath + "/" + AccessTokenFile
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
