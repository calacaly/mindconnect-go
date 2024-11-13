package agent

import (
	"encoding/json"
	"errors"

	"github.com/calacaly/mindconnect-go/internal/api/assetmanagement/v3/models"
	"github.com/calacaly/mindconnect-go/pkg/log"
)

func GetAssetList(token *string, filter string) ([]*models.AssetResource, error) {
	res, err := assetManagementClient.
		R().
		SetAuthToken(*token).
		SetHeader("Accept", "*/*").
		SetHeader("Content-Type", "application/json").
		SetQueryParam("filter", filter).
		Get("/assets")

	log.Logger.Info(res.Request.URL)

	if err != nil {
		return nil, err
	}

	if !res.IsSuccess() {
		err := errors.New(res.String() + res.Status())
		return nil, err
	}
	var assets models.AssetListResource
	err = json.Unmarshal(res.Body(), &assets)

	if err != nil {
		return nil, err
	}

	return assets.Embedded.Assets, nil
}
