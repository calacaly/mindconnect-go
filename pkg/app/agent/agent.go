package agent

import (
	"time"

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
	Token()
	Push()
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

	log.Logger.Info("start save client identifier")
	err = a.storage.Save(data, ClientIdentifierType)
	log.Logger.Info("save client identifier done")
	return err
}

func (a *Agent) Token() {

}

func (a *Agent) Push() {}

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
	return a.auth.GetClientIdentifier() != nil
}
