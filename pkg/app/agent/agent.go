package agent

import (
	"time"

	"github.com/calacaly/mindconnect-go/internal/api/agentmanagement/v3/models"
	"github.com/calacaly/mindconnect-go/pkg/log"
)

var (
	ServerHost       = "gateway.eu1.mindsphere.io"
	AgentApiEndPoint = "/api/agentmanagement/v3"
	SecretPath       = "./secrets"
)

type Agent struct {
	auth    Auther
	storage StorageClass
}

type AgentService interface {
	OnBoard() error
	Token() error
	Push() error
}

func (a *Agent) OnBoard() error {

	if a.IsOnBoarded() {
		log.Logger.Info("Already on boarded")
		return nil
	}

	log.Logger.Info("On boarding...")
	cid, err := a.auth.OnBoard()
	if err != nil {
		return err
	}

	data, err := cid.MarshalBinary()
	if err != nil {
		return err
	}

	log.Logger.Info(" save client identifier")
	err = a.storage.Save(data, ClientIdentifierType)
	log.Logger.Info("save client identifier done")
	return err
}

func (a *Agent) Token() error {
	access := a.auth.GetToken()
	if access != nil {
		log.Logger.Info("Already have access token")
		return nil
	}

	access, err := a.auth.AquireToken()
	if err != nil {
		return err
	}
	data, err := access.MarshalBinary()
	if err != nil {
		return err
	}
	log.Logger.Info("save access token")
	err = a.storage.Save(data, AccessTokenType)
	log.Logger.Info("save access token done")
	return err
}

func (a *Agent) Push() error {
	return nil
}

func NewAgentWithLocalStorage(secretPath string) AgentService {
	storage := NewLocalStorage(secretPath)
	auth := NewAuthWithStorageLoadConfig(3*time.Minute, storage)

	agent := Agent{
		auth:    auth,
		storage: storage,
	}

	return &agent
}

func (a *Agent) IsOnBoarded() bool {

	var cid models.ClientIdentifier
	if a.auth.GetClientIdentifier() == nil {
		if err := a.storage.GetConfig(&cid); err != nil {
			return false
		}
		return cid.RegistrationAccessToken != nil
	}
	cid = *a.auth.GetClientIdentifier()
	return cid.RegistrationAccessToken != nil
}
