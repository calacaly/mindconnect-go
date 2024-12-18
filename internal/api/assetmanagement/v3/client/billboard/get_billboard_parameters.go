// Code generated by go-swagger; DO NOT EDIT.

package billboard

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

// NewGetBillboardParams creates a new GetBillboardParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetBillboardParams() *GetBillboardParams {
	return &GetBillboardParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetBillboardParamsWithTimeout creates a new GetBillboardParams object
// with the ability to set a timeout on a request.
func NewGetBillboardParamsWithTimeout(timeout time.Duration) *GetBillboardParams {
	return &GetBillboardParams{
		timeout: timeout,
	}
}

// NewGetBillboardParamsWithContext creates a new GetBillboardParams object
// with the ability to set a context for a request.
func NewGetBillboardParamsWithContext(ctx context.Context) *GetBillboardParams {
	return &GetBillboardParams{
		Context: ctx,
	}
}

// NewGetBillboardParamsWithHTTPClient creates a new GetBillboardParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetBillboardParamsWithHTTPClient(client *http.Client) *GetBillboardParams {
	return &GetBillboardParams{
		HTTPClient: client,
	}
}

/*
GetBillboardParams contains all the parameters to send to the API endpoint

	for the get billboard operation.

	Typically these are written to a http.Request.
*/
type GetBillboardParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get billboard params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetBillboardParams) WithDefaults() *GetBillboardParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get billboard params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetBillboardParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get billboard params
func (o *GetBillboardParams) WithTimeout(timeout time.Duration) *GetBillboardParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get billboard params
func (o *GetBillboardParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get billboard params
func (o *GetBillboardParams) WithContext(ctx context.Context) *GetBillboardParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get billboard params
func (o *GetBillboardParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get billboard params
func (o *GetBillboardParams) WithHTTPClient(client *http.Client) *GetBillboardParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get billboard params
func (o *GetBillboardParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *GetBillboardParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
