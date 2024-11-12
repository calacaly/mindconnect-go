package agent

import (
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
		log.Logger.Info("Already on boarded")

		cid, err = a.auth.NewClientIdentifier()
		if err != nil {
			return err
		}

		if cid == nil {
			log.Logger.Info("client identifier not need to renew")
			return nil
		}
	} else {
		log.Logger.Info("On boarding...")
		cid, err = a.auth.OnBoard()
		if err != nil {
			return err
		}
	}

	data, err := cid.MarshalBinary()
	if err != nil {
		return err
	}

	log.Logger.Info(" save client identifier")
	err = a.storage.Save(data, store.ClientIdentifierType)
	log.Logger.Info("save client identifier done")
	return err
}

func (a *Agent) Token() (string, error) {
	access := a.auth.GetToken()
	if access != nil {
		log.Logger.Info("got access token")
		return access.AccessToken, nil
	}

	log.Logger.Info("renew access token")

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
	log.Logger.Info("get oauth public key")
	oauthPublicKey, err := a.auth.GetCertificate()

	if err == nil {
		log.Logger.Info("get oauth public key done")
		data, err := oauthPublicKey.MarshalBinary()
		if err != nil {
			log.Logger.Error("save oauth public key error", err)
		} else {
			err = a.storage.Save(data, store.OauthPublicKeyType)
			if err != nil {
				log.Logger.Error("save oauth public key error", err)
			}
		}
	} else {
		log.Logger.Warn("get oauth public key error:" + err.Error())
	}

	log.Logger.Info("init oauth client key")
	a.auth.InitDefaultOauthClientKey()

	var cfg models.Configuration
	err = a.storage.GetConfig(&cfg)
	if err != nil {
		log.Logger.Warn("Oauth", "load client configuration", err)
	} else {
		a.auth.SetConfiguration(&cfg)
	}

	var cid models.ClientIdentifier
	err = a.storage.GetConfig(&cid)
	if err != nil {
		log.Logger.Warn("Oauth", "load client identifier", err)
	} else {
		a.auth.SetClientIdentifier(&cid)
	}

	var pub models.TokenKey
	err = a.storage.GetConfig(&pub)
	if err != nil {
		log.Logger.Warn("Oauth", "load public key", err)
	} else {
		a.auth.SetOauthPublicKey(&pub)
	}

}
