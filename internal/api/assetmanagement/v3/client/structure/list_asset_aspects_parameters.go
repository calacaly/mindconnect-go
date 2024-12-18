// Code generated by go-swagger; DO NOT EDIT.

package structure

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

// NewListAssetAspectsParams creates a new ListAssetAspectsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListAssetAspectsParams() *ListAssetAspectsParams {
	return &ListAssetAspectsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListAssetAspectsParamsWithTimeout creates a new ListAssetAspectsParams object
// with the ability to set a timeout on a request.
func NewListAssetAspectsParamsWithTimeout(timeout time.Duration) *ListAssetAspectsParams {
	return &ListAssetAspectsParams{
		timeout: timeout,
	}
}

// NewListAssetAspectsParamsWithContext creates a new ListAssetAspectsParams object
// with the ability to set a context for a request.
func NewListAssetAspectsParamsWithContext(ctx context.Context) *ListAssetAspectsParams {
	return &ListAssetAspectsParams{
		Context: ctx,
	}
}

// NewListAssetAspectsParamsWithHTTPClient creates a new ListAssetAspectsParams object
// with the ability to set a custom HTTPClient for a request.
func NewListAssetAspectsParamsWithHTTPClient(client *http.Client) *ListAssetAspectsParams {
	return &ListAssetAspectsParams{
		HTTPClient: client,
	}
}

/*
ListAssetAspectsParams contains all the parameters to send to the API endpoint

	for the list asset aspects operation.

	Typically these are written to a http.Request.
*/
type ListAssetAspectsParams struct {

	/* IfNoneMatch.

	   ETag hash of previous request to allow caching
	*/
	IfNoneMatch *string

	/* Filter.

	   Specifies the additional filtering criteria
	*/
	Filter *string

	/* ID.

	   Unique identifier
	*/
	ID string

	/* IncludeShared.

	   Specifies if the operation should take into account shared (received) assets, aspects and asset types. Received resources are not visible in case includeShared=false. For query operations, received resources are not returned. Endpoints addressing individual resources respond with 404. In case received resources are referenced in a request parameter or property, they are treated as not existing.
	*/
	IncludeShared *bool

	/* Page.

	   Specifies the requested page index
	*/
	Page *int64

	/* Size.

	   Specifies the number of elements in a page (default size is 10)
	*/
	Size *int64

	/* Sort.

	   Specifies the ordering of returned elements
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list asset aspects params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListAssetAspectsParams) WithDefaults() *ListAssetAspectsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list asset aspects params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListAssetAspectsParams) SetDefaults() {
	var (
		includeSharedDefault = bool(false)
	)

	val := ListAssetAspectsParams{
		IncludeShared: &includeSharedDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the list asset aspects params
func (o *ListAssetAspectsParams) WithTimeout(timeout time.Duration) *ListAssetAspectsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list asset aspects params
func (o *ListAssetAspectsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list asset aspects params
func (o *ListAssetAspectsParams) WithContext(ctx context.Context) *ListAssetAspectsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list asset aspects params
func (o *ListAssetAspectsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list asset aspects params
func (o *ListAssetAspectsParams) WithHTTPClient(client *http.Client) *ListAssetAspectsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list asset aspects params
func (o *ListAssetAspectsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfNoneMatch adds the ifNoneMatch to the list asset aspects params
func (o *ListAssetAspectsParams) WithIfNoneMatch(ifNoneMatch *string) *ListAssetAspectsParams {
	o.SetIfNoneMatch(ifNoneMatch)
	return o
}

// SetIfNoneMatch adds the ifNoneMatch to the list asset aspects params
func (o *ListAssetAspectsParams) SetIfNoneMatch(ifNoneMatch *string) {
	o.IfNoneMatch = ifNoneMatch
}

// WithFilter adds the filter to the list asset aspects params
func (o *ListAssetAspectsParams) WithFilter(filter *string) *ListAssetAspectsParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the list asset aspects params
func (o *ListAssetAspectsParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithID adds the id to the list asset aspects params
func (o *ListAssetAspectsParams) WithID(id string) *ListAssetAspectsParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the list asset aspects params
func (o *ListAssetAspectsParams) SetID(id string) {
	o.ID = id
}

// WithIncludeShared adds the includeShared to the list asset aspects params
func (o *ListAssetAspectsParams) WithIncludeShared(includeShared *bool) *ListAssetAspectsParams {
	o.SetIncludeShared(includeShared)
	return o
}

// SetIncludeShared adds the includeShared to the list asset aspects params
func (o *ListAssetAspectsParams) SetIncludeShared(includeShared *bool) {
	o.IncludeShared = includeShared
}

// WithPage adds the page to the list asset aspects params
func (o *ListAssetAspectsParams) WithPage(page *int64) *ListAssetAspectsParams {
	o.SetPage(page)
	return o
}

// SetPage adds the page to the list asset aspects params
func (o *ListAssetAspectsParams) SetPage(page *int64) {
	o.Page = page
}

// WithSize adds the size to the list asset aspects params
func (o *ListAssetAspectsParams) WithSize(size *int64) *ListAssetAspectsParams {
	o.SetSize(size)
	return o
}

// SetSize adds the size to the list asset aspects params
func (o *ListAssetAspectsParams) SetSize(size *int64) {
	o.Size = size
}

// WithSort adds the sort to the list asset aspects params
func (o *ListAssetAspectsParams) WithSort(sort *string) *ListAssetAspectsParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the list asset aspects params
func (o *ListAssetAspectsParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *ListAssetAspectsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	if o.Filter != nil {

		// query param filter
		var qrFilter string

		if o.Filter != nil {
			qrFilter = *o.Filter
		}
		qFilter := qrFilter
		if qFilter != "" {

			if err := r.SetQueryParam("filter", qFilter); err != nil {
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

	if o.Page != nil {

		// query param page
		var qrPage int64

		if o.Page != nil {
			qrPage = *o.Page
		}
		qPage := swag.FormatInt64(qrPage)
		if qPage != "" {

			if err := r.SetQueryParam("page", qPage); err != nil {
				return err
			}
		}
	}

	if o.Size != nil {

		// query param size
		var qrSize int64

		if o.Size != nil {
			qrSize = *o.Size
		}
		qSize := swag.FormatInt64(qrSize)
		if qSize != "" {

			if err := r.SetQueryParam("size", qSize); err != nil {
				return err
			}
		}
	}

	if o.Sort != nil {

		// query param sort
		var qrSort string

		if o.Sort != nil {
			qrSort = *o.Sort
		}
		qSort := qrSort
		if qSort != "" {

			if err := r.SetQueryParam("sort", qSort); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
