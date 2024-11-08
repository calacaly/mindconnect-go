// Code generated by go-swagger; DO NOT EDIT.

package agent_operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new agent operations API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new agent operations API client with basic auth credentials.
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

// New creates a new agent operations API client with a bearer token for authentication.
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
Client for agent operations API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	DeleteAgentsID(params *DeleteAgentsIDParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteAgentsIDNoContent, error)

	GetAgents(params *GetAgentsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAgentsOK, error)

	GetAgentsID(params *GetAgentsIDParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAgentsIDOK, error)

	GetAgentsIDStatus(params *GetAgentsIDStatusParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAgentsIDStatusOK, error)

	PostAgents(params *PostAgentsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PostAgentsCreated, error)

	PutAgentsID(params *PutAgentsIDParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PutAgentsIDOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
DeleteAgentsID deletes agent

Deletes the agent for the given agent id.
*/
func (a *Client) DeleteAgentsID(params *DeleteAgentsIDParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteAgentsIDNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteAgentsIDParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "DeleteAgentsID",
		Method:             "DELETE",
		PathPattern:        "/agents/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteAgentsIDReader{formats: a.formats},
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
	success, ok := result.(*DeleteAgentsIDNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*DeleteAgentsIDDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
GetAgents gets agents

Gets the agents for the given filter.
*/
func (a *Client) GetAgents(params *GetAgentsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAgentsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAgentsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetAgents",
		Method:             "GET",
		PathPattern:        "/agents",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAgentsReader{formats: a.formats},
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
	success, ok := result.(*GetAgentsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*GetAgentsDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
GetAgentsID gets agent

Gets the agent for the given agent id.
*/
func (a *Client) GetAgentsID(params *GetAgentsIDParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAgentsIDOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAgentsIDParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetAgentsID",
		Method:             "GET",
		PathPattern:        "/agents/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAgentsIDReader{formats: a.formats},
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
	success, ok := result.(*GetAgentsIDOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*GetAgentsIDDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
GetAgentsIDStatus gets online status

Gets online status.
*/
func (a *Client) GetAgentsIDStatus(params *GetAgentsIDStatusParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAgentsIDStatusOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAgentsIDStatusParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetAgentsIDStatus",
		Method:             "GET",
		PathPattern:        "/agents/{id}/status",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAgentsIDStatusReader{formats: a.formats},
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
	success, ok := result.(*GetAgentsIDStatusOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*GetAgentsIDStatusDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
PostAgents creates agent

Creates a new agent.
*/
func (a *Client) PostAgents(params *PostAgentsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PostAgentsCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPostAgentsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PostAgents",
		Method:             "POST",
		PathPattern:        "/agents",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PostAgentsReader{formats: a.formats},
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
	success, ok := result.(*PostAgentsCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*PostAgentsDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
PutAgentsID updates agent

Updates the agent for the given agent id with given parameters.
*/
func (a *Client) PutAgentsID(params *PutAgentsIDParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PutAgentsIDOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPutAgentsIDParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PutAgentsID",
		Method:             "PUT",
		PathPattern:        "/agents/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PutAgentsIDReader{formats: a.formats},
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
	success, ok := result.(*PutAgentsIDOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*PutAgentsIDDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
