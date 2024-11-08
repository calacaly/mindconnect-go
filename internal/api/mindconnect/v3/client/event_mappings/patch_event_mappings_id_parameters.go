// Code generated by go-swagger; DO NOT EDIT.

package event_mappings

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

	"github.com/calacaly/mindconnect-go/internal/api/mindconnect/v3/models"
)

// NewPatchEventMappingsIDParams creates a new PatchEventMappingsIDParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPatchEventMappingsIDParams() *PatchEventMappingsIDParams {
	return &PatchEventMappingsIDParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPatchEventMappingsIDParamsWithTimeout creates a new PatchEventMappingsIDParams object
// with the ability to set a timeout on a request.
func NewPatchEventMappingsIDParamsWithTimeout(timeout time.Duration) *PatchEventMappingsIDParams {
	return &PatchEventMappingsIDParams{
		timeout: timeout,
	}
}

// NewPatchEventMappingsIDParamsWithContext creates a new PatchEventMappingsIDParams object
// with the ability to set a context for a request.
func NewPatchEventMappingsIDParamsWithContext(ctx context.Context) *PatchEventMappingsIDParams {
	return &PatchEventMappingsIDParams{
		Context: ctx,
	}
}

// NewPatchEventMappingsIDParamsWithHTTPClient creates a new PatchEventMappingsIDParams object
// with the ability to set a custom HTTPClient for a request.
func NewPatchEventMappingsIDParamsWithHTTPClient(client *http.Client) *PatchEventMappingsIDParams {
	return &PatchEventMappingsIDParams{
		HTTPClient: client,
	}
}

/*
PatchEventMappingsIDParams contains all the parameters to send to the API endpoint

	for the patch event mappings ID operation.

	Typically these are written to a http.Request.
*/
type PatchEventMappingsIDParams struct {

	/* IfMatch.

	   ETag number of resource.
	*/
	IfMatch string

	/* ID.

	   Unique identifier of the mapping resource.
	*/
	ID string

	/* Mapping.

	   Object describing new values of the attributes of the mapping.
	*/
	Mapping *models.EventMappingOptional

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the patch event mappings ID params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PatchEventMappingsIDParams) WithDefaults() *PatchEventMappingsIDParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the patch event mappings ID params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PatchEventMappingsIDParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the patch event mappings ID params
func (o *PatchEventMappingsIDParams) WithTimeout(timeout time.Duration) *PatchEventMappingsIDParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the patch event mappings ID params
func (o *PatchEventMappingsIDParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the patch event mappings ID params
func (o *PatchEventMappingsIDParams) WithContext(ctx context.Context) *PatchEventMappingsIDParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the patch event mappings ID params
func (o *PatchEventMappingsIDParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the patch event mappings ID params
func (o *PatchEventMappingsIDParams) WithHTTPClient(client *http.Client) *PatchEventMappingsIDParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the patch event mappings ID params
func (o *PatchEventMappingsIDParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the patch event mappings ID params
func (o *PatchEventMappingsIDParams) WithIfMatch(ifMatch string) *PatchEventMappingsIDParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the patch event mappings ID params
func (o *PatchEventMappingsIDParams) SetIfMatch(ifMatch string) {
	o.IfMatch = ifMatch
}

// WithID adds the id to the patch event mappings ID params
func (o *PatchEventMappingsIDParams) WithID(id string) *PatchEventMappingsIDParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the patch event mappings ID params
func (o *PatchEventMappingsIDParams) SetID(id string) {
	o.ID = id
}

// WithMapping adds the mapping to the patch event mappings ID params
func (o *PatchEventMappingsIDParams) WithMapping(mapping *models.EventMappingOptional) *PatchEventMappingsIDParams {
	o.SetMapping(mapping)
	return o
}

// SetMapping adds the mapping to the patch event mappings ID params
func (o *PatchEventMappingsIDParams) SetMapping(mapping *models.EventMappingOptional) {
	o.Mapping = mapping
}

// WriteToRequest writes these params to a swagger request
func (o *PatchEventMappingsIDParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// header param If-Match
	if err := r.SetHeaderParam("If-Match", o.IfMatch); err != nil {
		return err
	}

	// path param id
	if err := r.SetPathParam("id", o.ID); err != nil {
		return err
	}
	if o.Mapping != nil {
		if err := r.SetBodyParam(o.Mapping); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}