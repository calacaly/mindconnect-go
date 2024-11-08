// Code generated by go-swagger; DO NOT EDIT.

package boarding_operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new boarding operations API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new boarding operations API client with basic auth credentials.
// It takes the following parameters:
// - host: http host (github.com).
// - basePath: any base path for the API client ("/v1", "/v3").
// - scheme: http scheme ("http", "https").
// - user: user for basic authentication header.
// - password: password for basic authentication header.
func NewClientWithBasicAuth(host, basePath, scheme, user, password string) ClientService {
	transport := httptransport.New(host, basePath, []string{scheme})
	transport.DefaultAuthentication = httptransport.BasicAuth(user, password)
	return &Client{transport: transport, formats: strfmt.Default}
}

// New creates a new boarding operations API client with a bearer token for authentication.
// It takes the following parameters:
// - host: http host (github.com).
// - basePath: any base path for the API client ("/v1", "/v3").
// - scheme: http scheme ("http", "https").
// - bearerToken: bearer token for Bearer authentication header.
func NewClientWithBearerToken(host, basePath, scheme, bearerToken string) ClientService {
	transport := httptransport.New(host, basePath, []string{scheme})
	transport.DefaultAuthentication = httptransport.BearerToken(bearerToken)
	return &Client{transport: transport, formats: strfmt.Default}
}

/*
Client for boarding operations API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	GetAgentsIDBoardingConfiguration(params *GetAgentsIDBoardingConfigurationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAgentsIDBoardingConfigurationOK, error)

	GetAgentsIDBoardingStatus(params *GetAgentsIDBoardingStatusParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAgentsIDBoardingStatusOK, error)

	PostAgentsIDBoardingOffboard(params *PostAgentsIDBoardingOffboardParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PostAgentsIDBoardingOffboardOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
GetAgentsIDBoardingConfiguration gets boarding configuration

Boarding configuration holds necessary information of the agent to onboard it.(ex; iat, clientCredentialProfile). Generating a Boarding Configuration action is an asynchronous operation therefore it may take a few seconds. In case Boarding Configuration is not generated, try to read the configuration again after a couple of seconds.
*/
func (a *Client) GetAgentsIDBoardingConfiguration(params *GetAgentsIDBoardingConfigurationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAgentsIDBoardingConfigurationOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAgentsIDBoardingConfigurationParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetAgentsIDBoardingConfiguration",
		Method:             "GET",
		PathPattern:        "/agents/{id}/boarding/configuration",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAgentsIDBoardingConfigurationReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetAgentsIDBoardingConfigurationOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*GetAgentsIDBoardingConfigurationDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
GetAgentsIDBoardingStatus gets boarding status

Gets boarding status.
*/
func (a *Client) GetAgentsIDBoardingStatus(params *GetAgentsIDBoardingStatusParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAgentsIDBoardingStatusOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAgentsIDBoardingStatusParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetAgentsIDBoardingStatus",
		Method:             "GET",
		PathPattern:        "/agents/{id}/boarding/status",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAgentsIDBoardingStatusReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetAgentsIDBoardingStatusOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*GetAgentsIDBoardingStatusDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
PostAgentsIDBoardingOffboard offboards agent

Offboards the agent.
*/
func (a *Client) PostAgentsIDBoardingOffboard(params *PostAgentsIDBoardingOffboardParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PostAgentsIDBoardingOffboardOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPostAgentsIDBoardingOffboardParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PostAgentsIDBoardingOffboard",
		Method:             "POST",
		PathPattern:        "/agents/{id}/boarding/offboard",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PostAgentsIDBoardingOffboardReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*PostAgentsIDBoardingOffboardOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*PostAgentsIDBoardingOffboardDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
