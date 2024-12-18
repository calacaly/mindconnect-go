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

	"github.com/calacaly/mindconnect-go/internal/api/assetmanagement/v3/models"
)

// NewReplaceAssetParams creates a new ReplaceAssetParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewReplaceAssetParams() *ReplaceAssetParams {
	return &ReplaceAssetParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewReplaceAssetParamsWithTimeout creates a new ReplaceAssetParams object
// with the ability to set a timeout on a request.
func NewReplaceAssetParamsWithTimeout(timeout time.Duration) *ReplaceAssetParams {
	return &ReplaceAssetParams{
		timeout: timeout,
	}
}

// NewReplaceAssetParamsWithContext creates a new ReplaceAssetParams object
// with the ability to set a context for a request.
func NewReplaceAssetParamsWithContext(ctx context.Context) *ReplaceAssetParams {
	return &ReplaceAssetParams{
		Context: ctx,
	}
}

// NewReplaceAssetParamsWithHTTPClient creates a new ReplaceAssetParams object
// with the ability to set a custom HTTPClient for a request.
func NewReplaceAssetParamsWithHTTPClient(client *http.Client) *ReplaceAssetParams {
	return &ReplaceAssetParams{
		HTTPClient: client,
	}
}

/*
ReplaceAssetParams contains all the parameters to send to the API endpoint

	for the replace asset operation.

	Typically these are written to a http.Request.
*/
type ReplaceAssetParams struct {

	/* IfMatch.

	   Last known version to facilitate optimistic locking
	*/
	IfMatch string

	/* Asset.

	   asset
	*/
	Asset *models.AssetUpdate

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

// WithDefaults hydrates default values in the replace asset params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ReplaceAssetParams) WithDefaults() *ReplaceAssetParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the replace asset params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ReplaceAssetParams) SetDefaults() {
	var (
		includeSharedDefault = bool(false)
	)

	val := ReplaceAssetParams{
		IncludeShared: &includeSharedDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the replace asset params
func (o *ReplaceAssetParams) WithTimeout(timeout time.Duration) *ReplaceAssetParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the replace asset params
func (o *ReplaceAssetParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the replace asset params
func (o *ReplaceAssetParams) WithContext(ctx context.Context) *ReplaceAssetParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the replace asset params
func (o *ReplaceAssetParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the replace asset params
func (o *ReplaceAssetParams) WithHTTPClient(client *http.Client) *ReplaceAssetParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the replace asset params
func (o *ReplaceAssetParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the replace asset params
func (o *ReplaceAssetParams) WithIfMatch(ifMatch string) *ReplaceAssetParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the replace asset params
func (o *ReplaceAssetParams) SetIfMatch(ifMatch string) {
	o.IfMatch = ifMatch
}

// WithAsset adds the asset to the replace asset params
func (o *ReplaceAssetParams) WithAsset(asset *models.AssetUpdate) *ReplaceAssetParams {
	o.SetAsset(asset)
	return o
}

// SetAsset adds the asset to the replace asset params
func (o *ReplaceAssetParams) SetAsset(asset *models.AssetUpdate) {
	o.Asset = asset
}

// WithID adds the id to the replace asset params
func (o *ReplaceAssetParams) WithID(id string) *ReplaceAssetParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the replace asset params
func (o *ReplaceAssetParams) SetID(id string) {
	o.ID = id
}

// WithIncludeShared adds the includeShared to the replace asset params
func (o *ReplaceAssetParams) WithIncludeShared(includeShared *bool) *ReplaceAssetParams {
	o.SetIncludeShared(includeShared)
	return o
}

// SetIncludeShared adds the includeShared to the replace asset params
func (o *ReplaceAssetParams) SetIncludeShared(includeShared *bool) {
	o.IncludeShared = includeShared
}

// WriteToRequest writes these params to a swagger request
func (o *ReplaceAssetParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// header param If-Match
	if err := r.SetHeaderParam("If-Match", o.IfMatch); err != nil {
		return err
	}
	if o.Asset != nil {
		if err := r.SetBodyParam(o.Asset); err != nil {
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
