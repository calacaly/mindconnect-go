// Code generated by go-swagger; DO NOT EDIT.

package token_operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewPostOauthTokenParams creates a new PostOauthTokenParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPostOauthTokenParams() *PostOauthTokenParams {
	return &PostOauthTokenParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPostOauthTokenParamsWithTimeout creates a new PostOauthTokenParams object
// with the ability to set a timeout on a request.
func NewPostOauthTokenParamsWithTimeout(timeout time.Duration) *PostOauthTokenParams {
	return &PostOauthTokenParams{
		timeout: timeout,
	}
}

// NewPostOauthTokenParamsWithContext creates a new PostOauthTokenParams object
// with the ability to set a context for a request.
func NewPostOauthTokenParamsWithContext(ctx context.Context) *PostOauthTokenParams {
	return &PostOauthTokenParams{
		Context: ctx,
	}
}

// NewPostOauthTokenParamsWithHTTPClient creates a new PostOauthTokenParams object
// with the ability to set a custom HTTPClient for a request.
func NewPostOauthTokenParamsWithHTTPClient(client *http.Client) *PostOauthTokenParams {
	return &PostOauthTokenParams{
		HTTPClient: client,
	}
}

/*
PostOauthTokenParams contains all the parameters to send to the API endpoint

	for the post oauth token operation.

	Typically these are written to a http.Request.
*/
type PostOauthTokenParams struct {

	/* ClientAssertion.

	     A jwt which is signed with client secret

	Signing keys (client secret) can vary depending on agent security profile:<br>
	    - __SHARED_SECRET__: Client secret is provided by '/register' | ‘/register/<client_id>’ endpoint
	    - __RSA_3072__: Private part of the client's RSA key which the public part was provided at '/register' | '/register/<client_id>’
	    - __CACertifiedX509__: Private counterpart of device certificate’s public key.

	*/
	ClientAssertion string

	/* ClientAssertionType.

	   Defines the assertion type, only urn:ietf:params:oauth:client-assertion-type:jwt-bearer is supported.
	*/
	ClientAssertionType string

	/* GrantType.

	   The type of authentication being used to obtain the token, only  client_credentials is supported.
	*/
	GrantType string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the post oauth token params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostOauthTokenParams) WithDefaults() *PostOauthTokenParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the post oauth token params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostOauthTokenParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the post oauth token params
func (o *PostOauthTokenParams) WithTimeout(timeout time.Duration) *PostOauthTokenParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the post oauth token params
func (o *PostOauthTokenParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the post oauth token params
func (o *PostOauthTokenParams) WithContext(ctx context.Context) *PostOauthTokenParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the post oauth token params
func (o *PostOauthTokenParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the post oauth token params
func (o *PostOauthTokenParams) WithHTTPClient(client *http.Client) *PostOauthTokenParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the post oauth token params
func (o *PostOauthTokenParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithClientAssertion adds the clientAssertion to the post oauth token params
func (o *PostOauthTokenParams) WithClientAssertion(clientAssertion string) *PostOauthTokenParams {
	o.SetClientAssertion(clientAssertion)
	return o
}

// SetClientAssertion adds the clientAssertion to the post oauth token params
func (o *PostOauthTokenParams) SetClientAssertion(clientAssertion string) {
	o.ClientAssertion = clientAssertion
}

// WithClientAssertionType adds the clientAssertionType to the post oauth token params
func (o *PostOauthTokenParams) WithClientAssertionType(clientAssertionType string) *PostOauthTokenParams {
	o.SetClientAssertionType(clientAssertionType)
	return o
}

// SetClientAssertionType adds the clientAssertionType to the post oauth token params
func (o *PostOauthTokenParams) SetClientAssertionType(clientAssertionType string) {
	o.ClientAssertionType = clientAssertionType
}

// WithGrantType adds the grantType to the post oauth token params
func (o *PostOauthTokenParams) WithGrantType(grantType string) *PostOauthTokenParams {
	o.SetGrantType(grantType)
	return o
}

// SetGrantType adds the grantType to the post oauth token params
func (o *PostOauthTokenParams) SetGrantType(grantType string) {
	o.GrantType = grantType
}

// WriteToRequest writes these params to a swagger request
func (o *PostOauthTokenParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// form param client_assertion
	frClientAssertion := o.ClientAssertion
	fClientAssertion := frClientAssertion
	if fClientAssertion != "" {
		if err := r.SetFormParam("client_assertion", fClientAssertion); err != nil {
			return err
		}
	}

	// form param client_assertion_type
	frClientAssertionType := o.ClientAssertionType
	fClientAssertionType := frClientAssertionType
	if fClientAssertionType != "" {
		if err := r.SetFormParam("client_assertion_type", fClientAssertionType); err != nil {
			return err
		}
	}

	// form param grant_type
	frGrantType := o.GrantType
	fGrantType := frGrantType
	if fGrantType != "" {
		if err := r.SetFormParam("grant_type", fGrantType); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}