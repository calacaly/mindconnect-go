// Code generated by go-swagger; DO NOT EDIT.

package client

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/calacaly/mindconnect-go/internal/api/assetmanagement/v3/client/aspecttype"
	"github.com/calacaly/mindconnect-go/internal/api/assetmanagement/v3/client/assetmodellock"
	"github.com/calacaly/mindconnect-go/internal/api/assetmanagement/v3/client/assets"
	"github.com/calacaly/mindconnect-go/internal/api/assetmanagement/v3/client/assettype"
	"github.com/calacaly/mindconnect-go/internal/api/assetmanagement/v3/client/billboard"
	"github.com/calacaly/mindconnect-go/internal/api/assetmanagement/v3/client/files"
	"github.com/calacaly/mindconnect-go/internal/api/assetmanagement/v3/client/locations"
	"github.com/calacaly/mindconnect-go/internal/api/assetmanagement/v3/client/structure"
)

// Default asset management API HTTP client.
var Default = NewHTTPClient(nil)

const (
	// DefaultHost is the default Host
	// found in Meta (info) section of spec file
	DefaultHost string = "localhost"
	// DefaultBasePath is the default BasePath
	// found in Meta (info) section of spec file
	DefaultBasePath string = "/api/assetmanagement/v3"
)

// DefaultSchemes are the default schemes found in Meta (info) section of spec file
var DefaultSchemes = []string{"https"}

// NewHTTPClient creates a new asset management API HTTP client.
func NewHTTPClient(formats strfmt.Registry) *AssetManagementAPI {
	return NewHTTPClientWithConfig(formats, nil)
}

// NewHTTPClientWithConfig creates a new asset management API HTTP client,
// using a customizable transport config.
func NewHTTPClientWithConfig(formats strfmt.Registry, cfg *TransportConfig) *AssetManagementAPI {
	// ensure nullable parameters have default
	if cfg == nil {
		cfg = DefaultTransportConfig()
	}

	// create transport and client
	transport := httptransport.New(cfg.Host, cfg.BasePath, cfg.Schemes)
	return New(transport, formats)
}

// New creates a new asset management API client
func New(transport runtime.ClientTransport, formats strfmt.Registry) *AssetManagementAPI {
	// ensure nullable parameters have default
	if formats == nil {
		formats = strfmt.Default
	}

	cli := new(AssetManagementAPI)
	cli.Transport = transport
	cli.Aspecttype = aspecttype.New(transport, formats)
	cli.Assetmodellock = assetmodellock.New(transport, formats)
	cli.Assets = assets.New(transport, formats)
	cli.Assettype = assettype.New(transport, formats)
	cli.Billboard = billboard.New(transport, formats)
	cli.Files = files.New(transport, formats)
	cli.Locations = locations.New(transport, formats)
	cli.Structure = structure.New(transport, formats)
	return cli
}

// DefaultTransportConfig creates a TransportConfig with the
// default settings taken from the meta section of the spec file.
func DefaultTransportConfig() *TransportConfig {
	return &TransportConfig{
		Host:     DefaultHost,
		BasePath: DefaultBasePath,
		Schemes:  DefaultSchemes,
	}
}

// TransportConfig contains the transport related info,
// found in the meta section of the spec file.
type TransportConfig struct {
	Host     string
	BasePath string
	Schemes  []string
}

// WithHost overrides the default host,
// provided by the meta section of the spec file.
func (cfg *TransportConfig) WithHost(host string) *TransportConfig {
	cfg.Host = host
	return cfg
}

// WithBasePath overrides the default basePath,
// provided by the meta section of the spec file.
func (cfg *TransportConfig) WithBasePath(basePath string) *TransportConfig {
	cfg.BasePath = basePath
	return cfg
}

// WithSchemes overrides the default schemes,
// provided by the meta section of the spec file.
func (cfg *TransportConfig) WithSchemes(schemes []string) *TransportConfig {
	cfg.Schemes = schemes
	return cfg
}

// AssetManagementAPI is a client for asset management API
type AssetManagementAPI struct {
	Aspecttype aspecttype.ClientService

	Assetmodellock assetmodellock.ClientService

	Assets assets.ClientService

	Assettype assettype.ClientService

	Billboard billboard.ClientService

	Files files.ClientService

	Locations locations.ClientService

	Structure structure.ClientService

	Transport runtime.ClientTransport
}

// SetTransport changes the transport on the client and all its subresources
func (c *AssetManagementAPI) SetTransport(transport runtime.ClientTransport) {
	c.Transport = transport
	c.Aspecttype.SetTransport(transport)
	c.Assetmodellock.SetTransport(transport)
	c.Assets.SetTransport(transport)
	c.Assettype.SetTransport(transport)
	c.Billboard.SetTransport(transport)
	c.Files.SetTransport(transport)
	c.Locations.SetTransport(transport)
	c.Structure.SetTransport(transport)
}
