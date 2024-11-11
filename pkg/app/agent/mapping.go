package agent

import "github.com/calacaly/mindconnect-go/internal/api/agentmanagement/v3/models"

func GetDataSourceConfiguration() models.DataSourceConfiguration {
	return models.DataSourceConfiguration{}
}

func HasDataSourceConfiguration() bool {
	return true
}

func ApplyDataSourceConfiguration() {}

func calculateEtag() string {
	return ""
}

func HasDataMappings() bool {
	return true
}
func GetDataMappings() string {
	return ""
}

func GenerateDataSourceConfiguration() models.DataSourceConfiguration {
	return models.DataSourceConfiguration{}
}

func GenerateMappings() string {
	return ""
}
