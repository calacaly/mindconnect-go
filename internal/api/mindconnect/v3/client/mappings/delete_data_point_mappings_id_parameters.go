// Code generated by go-swagger; DO NOT EDIT.

package mappings

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

// NewDeleteDataPointMappingsIDParams creates a new DeleteDataPointMappingsIDParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeleteDataPointMappingsIDParams() *DeleteDataPointMappingsIDParams {
	return &DeleteDataPointMappingsIDParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteDataPointMappingsIDParamsWithTimeout creates a new DeleteDataPointMappingsIDParams object
// with the ability to set a timeout on a request.
func NewDeleteDataPointMappingsIDParamsWithTimeout(timeout time.Duration) *DeleteDataPointMappingsIDParams {
	return &DeleteDataPointMappingsIDParams{
		timeout: timeout,
	}
}

// NewDeleteDataPointMappingsIDParamsWithContext creates a new DeleteDataPointMappingsIDParams object
// with the ability to set a context for a request.
func NewDeleteDataPointMappingsIDParamsWithContext(ctx context.Context) *DeleteDataPointMappingsIDParams {
	return &DeleteDataPointMappingsIDParams{
		Context: ctx,
	}
}

// NewDeleteDataPointMappingsIDParamsWithHTTPClient creates a new DeleteDataPointMappingsIDParams object
// with the ability to set a custom HTTPClient for a request.
func NewDeleteDataPointMappingsIDParamsWithHTTPClient(client *http.Client) *DeleteDataPointMappingsIDParams {
	return &DeleteDataPointMappingsIDParams{
		HTTPClient: client,
	}
}

/*
DeleteDataPointMappingsIDParams contains all the parameters to send to the API endpoint

	for the delete data point mappings ID operation.

	Typically these are written to a http.Request.
*/
type DeleteDataPointMappingsIDParams struct {

	/* ID.

	   Unique identifier of the mapping resource.
	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the delete data point mappings ID params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteDataPointMappingsIDParams) WithDefaults() *DeleteDataPointMappingsIDParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the delete data point mappings ID params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteDataPointMappingsIDParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the delete data point mappings ID params
func (o *DeleteDataPointMappingsIDParams) WithTimeout(timeout time.Duration) *DeleteDataPointMappingsIDParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete data point mappings ID params
func (o *DeleteDataPointMappingsIDParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete data point mappings ID params
func (o *DeleteDataPointMappingsIDParams) WithContext(ctx context.Context) *DeleteDataPointMappingsIDParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete data point mappings ID params
func (o *DeleteDataPointMappingsIDParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete data point mappings ID params
func (o *DeleteDataPointMappingsIDParams) WithHTTPClient(client *http.Client) *DeleteDataPointMappingsIDParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete data point mappings ID params
func (o *DeleteDataPointMappingsIDParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the delete data point mappings ID params
func (o *DeleteDataPointMappingsIDParams) WithID(id string) *DeleteDataPointMappingsIDParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the delete data point mappings ID params
func (o *DeleteDataPointMappingsIDParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteDataPointMappingsIDParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param id
	if err := r.SetPathParam("id", o.ID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
