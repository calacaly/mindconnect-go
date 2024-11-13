package agent

import (
	"github.com/calacaly/mindconnect-go/internal/api/agentmanagement/v3/client/data_source_configuration_operations"
	"github.com/calacaly/mindconnect-go/internal/api/agentmanagement/v3/models"
	httptransport "github.com/go-openapi/runtime/client"
)

func (a *Agent) GetDataSourceConfig(token *string) (*models.DataSourceConfiguration, error) {

	authInfo := httptransport.BearerToken(*token)
	res, err := agentManagementApi.DataSourceConfigurationOperations.GetAgentsIDDataSourceConfiguration(
		data_source_configuration_operations.NewGetAgentsIDDataSourceConfigurationParams().
			WithDefaults().
			WithID(a.auth.GetConfiguration().Content.ClientID),
		authInfo,
	)

	if err != nil {
		return nil, err
	}

	return res.Payload, nil
}

func (a *Agent) SetDataSourceConfig(token *string, config *models.UpdateDataSourceConfigurationRequest) error {
	authInfo := httptransport.BearerToken(*token)
	_, err := agentManagementApi.DataSourceConfigurationOperations.PutAgentsIDDataSourceConfiguration(
		data_source_configuration_operations.NewPutAgentsIDDataSourceConfigurationParams().
			WithDefaults().
			WithID(a.auth.GetConfiguration().Content.ClientID).
			WithConfiguration(config),
		authInfo,
	)
	return err
}

func CreateDataSourceConfig() *models.UpdateDataSourceConfigurationRequest {
	id := "01"
	name := "mindconnect-go"

	datapoints := []*models.DataPoint{
		{},
	}
	dataSources := []*models.DataSource{
		{
			Name: &name,
			CustomData: map[string]interface{}{
				"test": "test",
			},
			DataPoints:  datapoints,
			Description: "test",
		},
	}
	return &models.UpdateDataSourceConfigurationRequest{
		ConfigurationID: &id,
		DataSources:     dataSources,
	}
}
