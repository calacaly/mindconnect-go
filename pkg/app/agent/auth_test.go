package agent

import (
	"testing"
	"time"
)

func TestGetCertificate(t *testing.T) {
	auth := NewAuth(3*time.Minute, 24*time.Hour)
	key, err := auth.GetCertificate()
	if err != nil {
		t.Error(err)
	}
	t.Logf("%+v", key)
}
