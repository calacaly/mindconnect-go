// Code generated by go-swagger; DO NOT EDIT.

package assets

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

// NewGetAssetParams creates a new GetAssetParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetAssetParams() *GetAssetParams {
	return &GetAssetParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetAssetParamsWithTimeout creates a new GetAssetParams object
// with the ability to set a timeout on a request.
func NewGetAssetParamsWithTimeout(timeout time.Duration) *GetAssetParams {
	return &GetAssetParams{
		timeout: timeout,
	}
}

// NewGetAssetParamsWithContext creates a new GetAssetParams object
// with the ability to set a context for a request.
func NewGetAssetParamsWithContext(ctx context.Context) *GetAssetParams {
	return &GetAssetParams{
		Context: ctx,
	}
}

// NewGetAssetParamsWithHTTPClient creates a new GetAssetParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetAssetParamsWithHTTPClient(client *http.Client) *GetAssetParams {
	return &GetAssetParams{
		HTTPClient: client,
	}
}

/*
GetAssetParams contains all the parameters to send to the API endpoint

	for the get asset operation.

	Typically these are written to a http.Request.
*/
type GetAssetParams struct {

	/* IfNoneMatch.

	   ETag hash of previous request to allow caching
	*/
	IfNoneMatch *string

	/* ID.

	   Unique identifier
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

// WithDefaults hydrates default values in the get asset params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAssetParams) WithDefaults() *GetAssetParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get asset params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAssetParams) SetDefaults() {
	var (
		includeSharedDefault = bool(false)
	)

	val := GetAssetParams{
		IncludeShared: &includeSharedDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get asset params
func (o *GetAssetParams) WithTimeout(timeout time.Duration) *GetAssetParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get asset params
func (o *GetAssetParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get asset params
func (o *GetAssetParams) WithContext(ctx context.Context) *GetAssetParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get asset params
func (o *GetAssetParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get asset params
func (o *GetAssetParams) WithHTTPClient(client *http.Client) *GetAssetParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get asset params
func (o *GetAssetParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfNoneMatch adds the ifNoneMatch to the get asset params
func (o *GetAssetParams) WithIfNoneMatch(ifNoneMatch *string) *GetAssetParams {
	o.SetIfNoneMatch(ifNoneMatch)
	return o
}

// SetIfNoneMatch adds the ifNoneMatch to the get asset params
func (o *GetAssetParams) SetIfNoneMatch(ifNoneMatch *string) {
	o.IfNoneMatch = ifNoneMatch
}

// WithID adds the id to the get asset params
func (o *GetAssetParams) WithID(id string) *GetAssetParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the get asset params
func (o *GetAssetParams) SetID(id string) {
	o.ID = id
}

// WithIncludeShared adds the includeShared to the get asset params
func (o *GetAssetParams) WithIncludeShared(includeShared *bool) *GetAssetParams {
	o.SetIncludeShared(includeShared)
	return o
}

// SetIncludeShared adds the includeShared to the get asset params
func (o *GetAssetParams) SetIncludeShared(includeShared *bool) {
	o.IncludeShared = includeShared
}

// WriteToRequest writes these params to a swagger request
func (o *GetAssetParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
