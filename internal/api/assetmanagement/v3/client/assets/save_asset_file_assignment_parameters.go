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

// NewSaveAssetFileAssignmentParams creates a new SaveAssetFileAssignmentParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewSaveAssetFileAssignmentParams() *SaveAssetFileAssignmentParams {
	return &SaveAssetFileAssignmentParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewSaveAssetFileAssignmentParamsWithTimeout creates a new SaveAssetFileAssignmentParams object
// with the ability to set a timeout on a request.
func NewSaveAssetFileAssignmentParamsWithTimeout(timeout time.Duration) *SaveAssetFileAssignmentParams {
	return &SaveAssetFileAssignmentParams{
		timeout: timeout,
	}
}

// NewSaveAssetFileAssignmentParamsWithContext creates a new SaveAssetFileAssignmentParams object
// with the ability to set a context for a request.
func NewSaveAssetFileAssignmentParamsWithContext(ctx context.Context) *SaveAssetFileAssignmentParams {
	return &SaveAssetFileAssignmentParams{
		Context: ctx,
	}
}

// NewSaveAssetFileAssignmentParamsWithHTTPClient creates a new SaveAssetFileAssignmentParams object
// with the ability to set a custom HTTPClient for a request.
func NewSaveAssetFileAssignmentParamsWithHTTPClient(client *http.Client) *SaveAssetFileAssignmentParams {
	return &SaveAssetFileAssignmentParams{
		HTTPClient: client,
	}
}

/*
SaveAssetFileAssignmentParams contains all the parameters to send to the API endpoint

	for the save asset file assignment operation.

	Typically these are written to a http.Request.
*/
type SaveAssetFileAssignmentParams struct {

	/* IfMatch.

	   Last known version to facilitate optimistic locking
	*/
	IfMatch string

	/* Assignment.

	   Data for file assignment
	*/
	Assignment *models.KeyedFileAssignment

	/* ID.

	   Unique identifier
	*/
	ID string

	/* IncludeShared.

	   Specifies if the operation should take into account shared (received) assets, aspects and asset types. Received resources are not visible in case includeShared=false. For query operations, received resources are not returned. Endpoints addressing individual resources respond with 404. In case received resources are referenced in a request parameter or property, they are treated as not existing.
	*/
	IncludeShared *bool

	/* Key.

	   Keyword for the file to be assigned to an asset or asset type.
	*/
	Key string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the save asset file assignment params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SaveAssetFileAssignmentParams) WithDefaults() *SaveAssetFileAssignmentParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the save asset file assignment params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SaveAssetFileAssignmentParams) SetDefaults() {
	var (
		includeSharedDefault = bool(false)
	)

	val := SaveAssetFileAssignmentParams{
		IncludeShared: &includeSharedDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the save asset file assignment params
func (o *SaveAssetFileAssignmentParams) WithTimeout(timeout time.Duration) *SaveAssetFileAssignmentParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the save asset file assignment params
func (o *SaveAssetFileAssignmentParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the save asset file assignment params
func (o *SaveAssetFileAssignmentParams) WithContext(ctx context.Context) *SaveAssetFileAssignmentParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the save asset file assignment params
func (o *SaveAssetFileAssignmentParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the save asset file assignment params
func (o *SaveAssetFileAssignmentParams) WithHTTPClient(client *http.Client) *SaveAssetFileAssignmentParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the save asset file assignment params
func (o *SaveAssetFileAssignmentParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the save asset file assignment params
func (o *SaveAssetFileAssignmentParams) WithIfMatch(ifMatch string) *SaveAssetFileAssignmentParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the save asset file assignment params
func (o *SaveAssetFileAssignmentParams) SetIfMatch(ifMatch string) {
	o.IfMatch = ifMatch
}

// WithAssignment adds the assignment to the save asset file assignment params
func (o *SaveAssetFileAssignmentParams) WithAssignment(assignment *models.KeyedFileAssignment) *SaveAssetFileAssignmentParams {
	o.SetAssignment(assignment)
	return o
}

// SetAssignment adds the assignment to the save asset file assignment params
func (o *SaveAssetFileAssignmentParams) SetAssignment(assignment *models.KeyedFileAssignment) {
	o.Assignment = assignment
}

// WithID adds the id to the save asset file assignment params
func (o *SaveAssetFileAssignmentParams) WithID(id string) *SaveAssetFileAssignmentParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the save asset file assignment params
func (o *SaveAssetFileAssignmentParams) SetID(id string) {
	o.ID = id
}

// WithIncludeShared adds the includeShared to the save asset file assignment params
func (o *SaveAssetFileAssignmentParams) WithIncludeShared(includeShared *bool) *SaveAssetFileAssignmentParams {
	o.SetIncludeShared(includeShared)
	return o
}

// SetIncludeShared adds the includeShared to the save asset file assignment params
func (o *SaveAssetFileAssignmentParams) SetIncludeShared(includeShared *bool) {
	o.IncludeShared = includeShared
}

// WithKey adds the key to the save asset file assignment params
func (o *SaveAssetFileAssignmentParams) WithKey(key string) *SaveAssetFileAssignmentParams {
	o.SetKey(key)
	return o
}

// SetKey adds the key to the save asset file assignment params
func (o *SaveAssetFileAssignmentParams) SetKey(key string) {
	o.Key = key
}

// WriteToRequest writes these params to a swagger request
func (o *SaveAssetFileAssignmentParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// header param If-Match
	if err := r.SetHeaderParam("If-Match", o.IfMatch); err != nil {
		return err
	}
	if o.Assignment != nil {
		if err := r.SetBodyParam(o.Assignment); err != nil {
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

	// path param key
	if err := r.SetPathParam("key", o.Key); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}