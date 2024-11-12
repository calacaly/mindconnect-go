package main

import (
	"github.com/calacaly/mindconnect-go/pkg/app/agent"
	"github.com/calacaly/mindconnect-go/pkg/log"
)

func main() {
	as := agent.NewAgentWithLocalStorage("./secrets")
	err := as.OnBoard()
	if err != nil {
		log.Logger.Error(err)
	}

	token, err := as.Token()
	if err != nil {
		log.Logger.Error(err)
	}
	log.Logger.Info(token)
}
