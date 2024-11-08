// Code generated by go-swagger; DO NOT EDIT.

package registration_operations

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

	"github.com/calacaly/mindconnect-go/internal/api/agentmanagement/v3/models"
)

// NewPutRegisterClientIDParams creates a new PutRegisterClientIDParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPutRegisterClientIDParams() *PutRegisterClientIDParams {
	return &PutRegisterClientIDParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPutRegisterClientIDParamsWithTimeout creates a new PutRegisterClientIDParams object
// with the ability to set a timeout on a request.
func NewPutRegisterClientIDParamsWithTimeout(timeout time.Duration) *PutRegisterClientIDParams {
	return &PutRegisterClientIDParams{
		timeout: timeout,
	}
}

// NewPutRegisterClientIDParamsWithContext creates a new PutRegisterClientIDParams object
// with the ability to set a context for a request.
func NewPutRegisterClientIDParamsWithContext(ctx context.Context) *PutRegisterClientIDParams {
	return &PutRegisterClientIDParams{
		Context: ctx,
	}
}

// NewPutRegisterClientIDParamsWithHTTPClient creates a new PutRegisterClientIDParams object
// with the ability to set a custom HTTPClient for a request.
func NewPutRegisterClientIDParamsWithHTTPClient(client *http.Client) *PutRegisterClientIDParams {
	return &PutRegisterClientIDParams{
		HTTPClient: client,
	}
}

/*
PutRegisterClientIDParams contains all the parameters to send to the API endpoint

	for the put register client ID operation.

	Typically these are written to a http.Request.
*/
type PutRegisterClientIDParams struct {

	/* Authorization.

	   Registration Access Token value with Bearer authentication scheme. e.g :Bearer eyJh...
	*/
	Authorization string

	/* ClientID.

	   Client identifier to update information.
	*/
	ClientID string

	/* Keys.

	   The client's key in JWKS for security profile RSA. If security profile is SHARED_SECRET there is only client_id in the JSON.
	*/
	Keys *models.RotationKeys

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the put register client ID params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PutRegisterClientIDParams) WithDefaults() *PutRegisterClientIDParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the put register client ID params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PutRegisterClientIDParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the put register client ID params
func (o *PutRegisterClientIDParams) WithTimeout(timeout time.Duration) *PutRegisterClientIDParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the put register client ID params
func (o *PutRegisterClientIDParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the put register client ID params
func (o *PutRegisterClientIDParams) WithContext(ctx context.Context) *PutRegisterClientIDParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the put register client ID params
func (o *PutRegisterClientIDParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the put register client ID params
func (o *PutRegisterClientIDParams) WithHTTPClient(client *http.Client) *PutRegisterClientIDParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the put register client ID params
func (o *PutRegisterClientIDParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAuthorization adds the authorization to the put register client ID params
func (o *PutRegisterClientIDParams) WithAuthorization(authorization string) *PutRegisterClientIDParams {
	o.SetAuthorization(authorization)
	return o
}

// SetAuthorization adds the authorization to the put register client ID params
func (o *PutRegisterClientIDParams) SetAuthorization(authorization string) {
	o.Authorization = authorization
}

// WithClientID adds the clientID to the put register client ID params
func (o *PutRegisterClientIDParams) WithClientID(clientID string) *PutRegisterClientIDParams {
	o.SetClientID(clientID)
	return o
}

// SetClientID adds the clientId to the put register client ID params
func (o *PutRegisterClientIDParams) SetClientID(clientID string) {
	o.ClientID = clientID
}

// WithKeys adds the keys to the put register client ID params
func (o *PutRegisterClientIDParams) WithKeys(keys *models.RotationKeys) *PutRegisterClientIDParams {
	o.SetKeys(keys)
	return o
}

// SetKeys adds the keys to the put register client ID params
func (o *PutRegisterClientIDParams) SetKeys(keys *models.RotationKeys) {
	o.Keys = keys
}

// WriteToRequest writes these params to a swagger request
func (o *PutRegisterClientIDParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// header param Authorization
	if err := r.SetHeaderParam("Authorization", o.Authorization); err != nil {
		return err
	}

	// path param client_id
	if err := r.SetPathParam("client_id", o.ClientID); err != nil {
		return err
	}
	if o.Keys != nil {
		if err := r.SetBodyParam(o.Keys); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
