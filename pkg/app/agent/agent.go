package agent

import (
	"crypto/rsa"
	"time"

	"github.com/calacaly/mindconnect-go/internal/api/agentmanagement/v3/models"
	"github.com/calacaly/mindconnect-go/pkg/log"

	"github.com/calacaly/mindconnect-go/pkg/store"
)

var (
	ServerHost       = "gateway.eu1.mindsphere.io"
	AgentApiEndPoint = "/api/agentmanagement/v3"
	SecretPath       = "./secrets"
)

type Agent struct {
	auth    Auther
	storage store.StorageClass
}

type AgentService interface {
	OnBoard() error
	Token() (string, error)
	Push() error
}

func (a *Agent) OnBoard() error {

	var cid *models.ClientIdentifier
	var err error
	if a.IsOnBoarded() {
		log.Logger.Info("Agent, agent already on boarded")

		cid, err = a.auth.NewClientIdentifier()
		if err != nil {
			return err
		}

		if cid == nil {
			log.Logger.Info("Agent, client identifier not need to renew")
			return nil
		}
	} else {
		log.Logger.Info("Agent", "agent on board", "ing...")
		cid, err = a.auth.OnBoard()
		if err != nil {
			return err
		}
	}

	data, err := cid.MarshalBinary()
	if err != nil {
		return err
	}

	log.Logger.Info("Agent", "save client identifier", "ing...")
	err = a.storage.Save(data, store.ClientIdentifierType)
	log.Logger.Info("Agent", "save client identifier", "done")
	return err
}

func (a *Agent) Token() (string, error) {
	access := a.auth.GetToken()
	if access != nil {
		log.Logger.Info("Agent", "get access token", "successed")
		return access.AccessToken, nil
	}

	log.Logger.Info("Agent, renew access token")

	access, err := a.auth.NewToken()

	if err != nil {
		return "", err
	}

	return access.AccessToken, nil
}

func (a *Agent) Push() error {
	return nil
}

func NewAgentWithLocalStorage(secretPath string) AgentService {
	storage := store.NewLocalStorage(secretPath)
	auth := NewAuth(3*time.Minute, 24*time.Hour)

	agent := Agent{
		auth:    auth,
		storage: storage,
	}

	agent.loadStorageConfig()

	return &agent
}

func (a *Agent) IsOnBoarded() bool {

	var cid models.ClientIdentifier
	if a.auth.GetClientIdentifier() == nil {
		err := a.storage.GetConfig(&cid)
		return err == nil
	} else {
		cid = *a.auth.GetClientIdentifier()
		return cid.RegistrationAccessToken != nil
	}
}

func (a *Agent) loadStorageConfig() {

	var oauthPublicKey models.TokenKey
	err := a.storage.GetConfig(&oauthPublicKey)
	if err != nil {
		log.Logger.Warn("Agent", "load oauth public key", err)
	} else {
		log.Logger.Info("Agent", "load oauth public key", "successed")
	}

	if oauthPublicKey.Value == "" {
		oauthPublicKey, err := a.auth.GetCertificate()

		if err == nil {
			log.Logger.Info("Agent", "get oauth public key", "done")
			data, err := oauthPublicKey.MarshalBinary()
			if err != nil {
				log.Logger.Error("Agent", "marshal oauth public key error", err)
			} else {
				err = a.storage.Save(data, store.OauthPublicKeyType)
				if err != nil {
					log.Logger.Error("Agent", "save oauth public key error", err)
				}
			}
		} else {
			log.Logger.Warn("Agent", "get oauth public key error", err)
		}
	}

	var cfg models.Configuration
	err = a.storage.GetConfig(&cfg)
	if err != nil {
		log.Logger.Warn("Agent", "load client configuration error", err)
	} else {
		log.Logger.Info("Agent", "load client configuration", "successed")
	}

	var cid models.ClientIdentifier
	err = a.storage.GetConfig(&cid)
	if err != nil {
		log.Logger.Warn("Agent", "load client identifier error", err)
	} else {
		log.Logger.Info("Agent", "load client identifier", "successed")
	}

	var publicKey rsa.PublicKey
	err = a.storage.GetConfig(&publicKey)
	if err != nil {
		log.Logger.Warn("Agent", "load public key error", err)
	} else {
		log.Logger.Info("Agent", "load public key", "successed")
	}

	var privateKey rsa.PrivateKey
	err = a.storage.GetConfig(&privateKey)
	if err != nil {
		log.Logger.Warn("Agent", "load private key error", err)
	} else {
		log.Logger.Info("Agent", "load private key", "successed")
	}

	// auth options
	a.auth.WithOptions(
		WithOauthPublicKey(&oauthPublicKey),
		WithClientIdentifier(&cid),
		WithConfiguration(&cfg),
		WithPublicKey(&publicKey),
		WithPrivateKey(&privateKey),
		WithDefaultOauthClientKey(),
	)

}
