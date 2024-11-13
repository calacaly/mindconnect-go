// Code generated by go-swagger; DO NOT EDIT.

package assettype

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

// NewSaveAssetTypeParams creates a new SaveAssetTypeParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewSaveAssetTypeParams() *SaveAssetTypeParams {
	return &SaveAssetTypeParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewSaveAssetTypeParamsWithTimeout creates a new SaveAssetTypeParams object
// with the ability to set a timeout on a request.
func NewSaveAssetTypeParamsWithTimeout(timeout time.Duration) *SaveAssetTypeParams {
	return &SaveAssetTypeParams{
		timeout: timeout,
	}
}

// NewSaveAssetTypeParamsWithContext creates a new SaveAssetTypeParams object
// with the ability to set a context for a request.
func NewSaveAssetTypeParamsWithContext(ctx context.Context) *SaveAssetTypeParams {
	return &SaveAssetTypeParams{
		Context: ctx,
	}
}

// NewSaveAssetTypeParamsWithHTTPClient creates a new SaveAssetTypeParams object
// with the ability to set a custom HTTPClient for a request.
func NewSaveAssetTypeParamsWithHTTPClient(client *http.Client) *SaveAssetTypeParams {
	return &SaveAssetTypeParams{
		HTTPClient: client,
	}
}

/*
SaveAssetTypeParams contains all the parameters to send to the API endpoint

	for the save asset type operation.

	Typically these are written to a http.Request.
*/
type SaveAssetTypeParams struct {

	/* IfMatch.

	     Last known version to facilitate optimistic locking.
	*Required for modification.

	*/
	IfMatch *string

	/* IfNoneMatch.

	   Set ifNoneMatch header to "*" for ensuring create request
	*/
	IfNoneMatch *string

	/* Assettype.

	   asset type
	*/
	Assettype *models.AssetType

	/* Exploded.

	   Specifies if the asset type should include all of it's inherited variables and aspects. Default is false.
	*/
	Exploded *bool

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

// WithDefaults hydrates default values in the save asset type params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SaveAssetTypeParams) WithDefaults() *SaveAssetTypeParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the save asset type params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SaveAssetTypeParams) SetDefaults() {
	var (
		includeSharedDefault = bool(false)
	)

	val := SaveAssetTypeParams{
		IncludeShared: &includeSharedDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the save asset type params
func (o *SaveAssetTypeParams) WithTimeout(timeout time.Duration) *SaveAssetTypeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the save asset type params
func (o *SaveAssetTypeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the save asset type params
func (o *SaveAssetTypeParams) WithContext(ctx context.Context) *SaveAssetTypeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the save asset type params
func (o *SaveAssetTypeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the save asset type params
func (o *SaveAssetTypeParams) WithHTTPClient(client *http.Client) *SaveAssetTypeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the save asset type params
func (o *SaveAssetTypeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the save asset type params
func (o *SaveAssetTypeParams) WithIfMatch(ifMatch *string) *SaveAssetTypeParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the save asset type params
func (o *SaveAssetTypeParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIfNoneMatch adds the ifNoneMatch to the save asset type params
func (o *SaveAssetTypeParams) WithIfNoneMatch(ifNoneMatch *string) *SaveAssetTypeParams {
	o.SetIfNoneMatch(ifNoneMatch)
	return o
}

// SetIfNoneMatch adds the ifNoneMatch to the save asset type params
func (o *SaveAssetTypeParams) SetIfNoneMatch(ifNoneMatch *string) {
	o.IfNoneMatch = ifNoneMatch
}

// WithAssettype adds the assettype to the save asset type params
func (o *SaveAssetTypeParams) WithAssettype(assettype *models.AssetType) *SaveAssetTypeParams {
	o.SetAssettype(assettype)
	return o
}

// SetAssettype adds the assettype to the save asset type params
func (o *SaveAssetTypeParams) SetAssettype(assettype *models.AssetType) {
	o.Assettype = assettype
}

// WithExploded adds the exploded to the save asset type params
func (o *SaveAssetTypeParams) WithExploded(exploded *bool) *SaveAssetTypeParams {
	o.SetExploded(exploded)
	return o
}

// SetExploded adds the exploded to the save asset type params
func (o *SaveAssetTypeParams) SetExploded(exploded *bool) {
	o.Exploded = exploded
}

// WithID adds the id to the save asset type params
func (o *SaveAssetTypeParams) WithID(id string) *SaveAssetTypeParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the save asset type params
func (o *SaveAssetTypeParams) SetID(id string) {
	o.ID = id
}

// WithIncludeShared adds the includeShared to the save asset type params
func (o *SaveAssetTypeParams) WithIncludeShared(includeShared *bool) *SaveAssetTypeParams {
	o.SetIncludeShared(includeShared)
	return o
}

// SetIncludeShared adds the includeShared to the save asset type params
func (o *SaveAssetTypeParams) SetIncludeShared(includeShared *bool) {
	o.IncludeShared = includeShared
}

// WriteToRequest writes these params to a swagger request
func (o *SaveAssetTypeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.IfMatch != nil {

		// header param If-Match
		if err := r.SetHeaderParam("If-Match", *o.IfMatch); err != nil {
			return err
		}
	}

	if o.IfNoneMatch != nil {

		// header param If-None-Match
		if err := r.SetHeaderParam("If-None-Match", *o.IfNoneMatch); err != nil {
			return err
		}
	}
	if o.Assettype != nil {
		if err := r.SetBodyParam(o.Assettype); err != nil {
			return err
		}
	}

	if o.Exploded != nil {

		// query param exploded
		var qrExploded bool

		if o.Exploded != nil {
			qrExploded = *o.Exploded
		}
		qExploded := swag.FormatBool(qrExploded)
		if qExploded != "" {

			if err := r.SetQueryParam("exploded", qExploded); err != nil {
				return err
			}
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