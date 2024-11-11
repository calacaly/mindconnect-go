package agent

import (
	"testing"
)

func TestNewAgentWithLocalStorage(t *testing.T) {
	agent := NewAgentWithLocalStorage("../../../secrets")
	err := agent.OnBoard()
	if err != nil {
		t.Error(err)
	}
}
