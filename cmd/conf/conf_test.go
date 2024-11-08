package conf

import (
	"testing"
)

func TestNewConfig(t *testing.T) {
	got, err := NewConfig("../../config.toml")

	if got == nil {
		t.Error(err.Error())
	}
	t.Logf("%+v", got)
}
