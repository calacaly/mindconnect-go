// Code generated by go-swagger; DO NOT EDIT.

package files

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new files API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new files API client with basic auth credentials.
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

// New creates a new files API client with a bearer token for authentication.
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
Client for files API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// This client is generated with a few options you might find useful for your swagger spec.
//
// Feel free to add you own set of options.

// WithContentType allows the client to force the Content-Type header
// to negotiate a specific Consumer from the server.
//
// You may use this option to set arbitrary extensions to your MIME media type.
func WithContentType(mime string) ClientOption {
	return func(r *runtime.ClientOperation) {
		r.ConsumesMediaTypes = []string{mime}
	}
}

// WithContentTypeApplicationJSON sets the Content-Type header to "application/json".
func WithContentTypeApplicationJSON(r *runtime.ClientOperation) {
	r.ConsumesMediaTypes = []string{"application/json"}
}

// WithContentTypeMultipartFormData sets the Content-Type header to "multipart/form-data".
func WithContentTypeMultipartFormData(r *runtime.ClientOperation) {
	r.ConsumesMediaTypes = []string{"multipart/form-data"}
}

// WithAccept allows the client to force the Accept header
// to negotiate a specific Producer from the server.
//
// You may use this option to set arbitrary extensions to your MIME media type.
func WithAccept(mime string) ClientOption {
	return func(r *runtime.ClientOperation) {
		r.ProducesMediaTypes = []string{mime}
	}
}

// WithAcceptApplicationBase64 sets the Accept header to "application/base64".
func WithAcceptApplicationBase64(r *runtime.ClientOperation) {
	r.ProducesMediaTypes = []string{"application/base64"}
}

// WithAcceptApplicationHalJSON sets the Accept header to "application/hal+json".
func WithAcceptApplicationHalJSON(r *runtime.ClientOperation) {
	r.ProducesMediaTypes = []string{"application/hal+json"}
}

// WithAcceptApplicationJSON sets the Accept header to "application/json".
func WithAcceptApplicationJSON(r *runtime.ClientOperation) {
	r.ProducesMediaTypes = []string{"application/json"}
}

// WithAcceptApplicationOctetStream sets the Accept header to "application/octet-stream".
func WithAcceptApplicationOctetStream(r *runtime.ClientOperation) {
	r.ProducesMediaTypes = []string{"application/octet-stream"}
}

// WithAcceptApplicationVndErrorJSON sets the Accept header to "application/vnd.error+json".
func WithAcceptApplicationVndErrorJSON(r *runtime.ClientOperation) {
	r.ProducesMediaTypes = []string{"application/vnd.error+json"}
}

// ClientService is the interface for Client methods
type ClientService interface {
	DeleteFile(params *DeleteFileParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteFileNoContent, error)

	DownloadFile(params *DownloadFileParams, authInfo runtime.ClientAuthInfoWriter, writer io.Writer, opts ...ClientOption) (*DownloadFileOK, error)

	GetFile(params *GetFileParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetFileOK, error)

	ListFiles(params *ListFilesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListFilesOK, error)

	ReplaceFile(params *ReplaceFileParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ReplaceFileOK, error)

	UploadFile(params *UploadFileParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UploadFileCreated, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
DeleteFile deletes a file

* Deletion is blocked if there are any file assignment with the given fileId.
*/
func (a *Client) DeleteFile(params *DeleteFileParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteFileNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteFileParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteFile",
		Method:             "DELETE",
		PathPattern:        "/files/{fileId}",
		ProducesMediaTypes: []string{"application/hal+json", "application/vnd.error+json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteFileReader{formats: a.formats},
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
	success, ok := result.(*DeleteFileNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteFile: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DownloadFile returns a file by its id

Returns a file by its id
*/
func (a *Client) DownloadFile(params *DownloadFileParams, authInfo runtime.ClientAuthInfoWriter, writer io.Writer, opts ...ClientOption) (*DownloadFileOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDownloadFileParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "downloadFile",
		Method:             "GET",
		PathPattern:        "/files/{fileId}/file",
		ProducesMediaTypes: []string{"application/base64", "application/octet-stream", "application/vnd.error+json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DownloadFileReader{formats: a.formats, writer: writer},
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
	success, ok := result.(*DownloadFileOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for downloadFile: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetFile returns a file s metadata by its id

Returns a file's metadata by its id
*/
func (a *Client) GetFile(params *GetFileParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetFileOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetFileParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getFile",
		Method:             "GET",
		PathPattern:        "/files/{fileId}",
		ProducesMediaTypes: []string{"application/hal+json", "application/vnd.error+json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetFileReader{formats: a.formats},
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
	success, ok := result.(*GetFileOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getFile: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ListFiles gets metadata of uploaded files

Returns all visible file metadata for the tenant. Will NOT return the files.
*/
func (a *Client) ListFiles(params *ListFilesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListFilesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListFilesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listFiles",
		Method:             "GET",
		PathPattern:        "/files",
		ProducesMediaTypes: []string{"application/hal+json", "application/vnd.error+json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListFilesReader{formats: a.formats},
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
	success, ok := result.(*ListFilesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listFiles: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	ReplaceFile updates a file

	Update a previously uploaded file

* Max file size is 5 MB.
*/
func (a *Client) ReplaceFile(params *ReplaceFileParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ReplaceFileOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewReplaceFileParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "replaceFile",
		Method:             "PUT",
		PathPattern:        "/files/{fileId}",
		ProducesMediaTypes: []string{"application/hal+json", "application/vnd.error+json"},
		ConsumesMediaTypes: []string{"multipart/form-data"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ReplaceFileReader{formats: a.formats},
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
	success, ok := result.(*ReplaceFileOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for replaceFile: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	UploadFile uploads files to be used in asset management

	* Uploaded files are only visible for the uploader tenant.

* Max file size is 5 MB.
*/
func (a *Client) UploadFile(params *UploadFileParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UploadFileCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUploadFileParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "uploadFile",
		Method:             "POST",
		PathPattern:        "/files",
		ProducesMediaTypes: []string{"application/hal+json", "application/vnd.error+json"},
		ConsumesMediaTypes: []string{"multipart/form-data"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UploadFileReader{formats: a.formats},
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
	success, ok := result.(*UploadFileCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for uploadFile: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
