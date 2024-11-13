// Code generated by go-swagger; DO NOT EDIT.

package aspecttype

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
	"github.com/go-openapi/swag"
)

// NewGetAspectTypeParams creates a new GetAspectTypeParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetAspectTypeParams() *GetAspectTypeParams {
	return &GetAspectTypeParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetAspectTypeParamsWithTimeout creates a new GetAspectTypeParams object
// with the ability to set a timeout on a request.
func NewGetAspectTypeParamsWithTimeout(timeout time.Duration) *GetAspectTypeParams {
	return &GetAspectTypeParams{
		timeout: timeout,
	}
}

// NewGetAspectTypeParamsWithContext creates a new GetAspectTypeParams object
// with the ability to set a context for a request.
func NewGetAspectTypeParamsWithContext(ctx context.Context) *GetAspectTypeParams {
	return &GetAspectTypeParams{
		Context: ctx,
	}
}

// NewGetAspectTypeParamsWithHTTPClient creates a new GetAspectTypeParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetAspectTypeParamsWithHTTPClient(client *http.Client) *GetAspectTypeParams {
	return &GetAspectTypeParams{
		HTTPClient: client,
	}
}

/*
GetAspectTypeParams contains all the parameters to send to the API endpoint

	for the get aspect type operation.

	Typically these are written to a http.Request.
*/
type GetAspectTypeParams struct {

	/* IfNoneMatch.

	   ETag hash of previous request to allow caching
	*/
	IfNoneMatch *string

	/* ID.

	   The type's id is a unique identifier. The id's length must be between 1 and 128 characters and matches the following symbols "A-Z", "a-z", "0-9", "_" and "." beginning with the tenant prefix what has a maximum of 8 characters. (e.g . ten_pref.type_id)
	*/
	ID string

	/* IncludeShared.

	   Specifies if the operation should take into account shared (received) assets, aspects and asset types. Received resources are not visible in case includeShared=false. For query operations, received resources are not returned. Endpoints addressing individual resources respond with 404. In case received resources are referenced in a request parameter or property, they are treated as not existing.
	*/
	IncludeShared *bool

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get aspect type params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAspectTypeParams) WithDefaults() *GetAspectTypeParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get aspect type params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAspectTypeParams) SetDefaults() {
	var (
		includeSharedDefault = bool(false)
	)

	val := GetAspectTypeParams{
		IncludeShared: &includeSharedDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get aspect type params
func (o *GetAspectTypeParams) WithTimeout(timeout time.Duration) *GetAspectTypeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get aspect type params
func (o *GetAspectTypeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get aspect type params
func (o *GetAspectTypeParams) WithContext(ctx context.Context) *GetAspectTypeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get aspect type params
func (o *GetAspectTypeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get aspect type params
func (o *GetAspectTypeParams) WithHTTPClient(client *http.Client) *GetAspectTypeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get aspect type params
func (o *GetAspectTypeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfNoneMatch adds the ifNoneMatch to the get aspect type params
func (o *GetAspectTypeParams) WithIfNoneMatch(ifNoneMatch *string) *GetAspectTypeParams {
	o.SetIfNoneMatch(ifNoneMatch)
	return o
}

// SetIfNoneMatch adds the ifNoneMatch to the get aspect type params
func (o *GetAspectTypeParams) SetIfNoneMatch(ifNoneMatch *string) {
	o.IfNoneMatch = ifNoneMatch
}

// WithID adds the id to the get aspect type params
func (o *GetAspectTypeParams) WithID(id string) *GetAspectTypeParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the get aspect type params
func (o *GetAspectTypeParams) SetID(id string) {
	o.ID = id
}

// WithIncludeShared adds the includeShared to the get aspect type params
func (o *GetAspectTypeParams) WithIncludeShared(includeShared *bool) *GetAspectTypeParams {
	o.SetIncludeShared(includeShared)
	return o
}

// SetIncludeShared adds the includeShared to the get aspect type params
func (o *GetAspectTypeParams) SetIncludeShared(includeShared *bool) {
	o.IncludeShared = includeShared
}

// WriteToRequest writes these params to a swagger request
func (o *GetAspectTypeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.IfNoneMatch != nil {

		// header param If-None-Match
		if err := r.SetHeaderParam("If-None-Match", *o.IfNoneMatch); err != nil {
			return err
		}
	}

	// path param id
	if err := r.SetPathParam("id", o.ID); err != nil {
		return err
	}

	if o.IncludeShared != nil {

		// query param includeShared
		var qrIncludeShared bool

		if o.IncludeShared != nil {
			qrIncludeShared = *o.IncludeShared
		}
		qIncludeShared := swag.FormatBool(qrIncludeShared)
		if qIncludeShared != "" {

			if err := r.SetQueryParam("includeShared", qIncludeShared); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}