// Code generated by go-swagger; DO NOT EDIT.

package files

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

// NewListFilesParams creates a new ListFilesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListFilesParams() *ListFilesParams {
	return &ListFilesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListFilesParamsWithTimeout creates a new ListFilesParams object
// with the ability to set a timeout on a request.
func NewListFilesParamsWithTimeout(timeout time.Duration) *ListFilesParams {
	return &ListFilesParams{
		timeout: timeout,
	}
}

// NewListFilesParamsWithContext creates a new ListFilesParams object
// with the ability to set a context for a request.
func NewListFilesParamsWithContext(ctx context.Context) *ListFilesParams {
	return &ListFilesParams{
		Context: ctx,
	}
}

// NewListFilesParamsWithHTTPClient creates a new ListFilesParams object
// with the ability to set a custom HTTPClient for a request.
func NewListFilesParamsWithHTTPClient(client *http.Client) *ListFilesParams {
	return &ListFilesParams{
		HTTPClient: client,
	}
}

/*
ListFilesParams contains all the parameters to send to the API endpoint

	for the list files operation.

	Typically these are written to a http.Request.
*/
type ListFilesParams struct {

	/* IfNoneMatch.

	   ETag hash of previous request to allow caching
	*/
	IfNoneMatch *string

	/* Filter.

	   Specifies the additional filtering criteria
	*/
	Filter *string

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

// WithDefaults hydrates default values in the list files params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListFilesParams) WithDefaults() *ListFilesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list files params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListFilesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the list files params
func (o *ListFilesParams) WithTimeout(timeout time.Duration) *ListFilesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list files params
func (o *ListFilesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list files params
func (o *ListFilesParams) WithContext(ctx context.Context) *ListFilesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list files params
func (o *ListFilesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list files params
func (o *ListFilesParams) WithHTTPClient(client *http.Client) *ListFilesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list files params
func (o *ListFilesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfNoneMatch adds the ifNoneMatch to the list files params
func (o *ListFilesParams) WithIfNoneMatch(ifNoneMatch *string) *ListFilesParams {
	o.SetIfNoneMatch(ifNoneMatch)
	return o
}

// SetIfNoneMatch adds the ifNoneMatch to the list files params
func (o *ListFilesParams) SetIfNoneMatch(ifNoneMatch *string) {
	o.IfNoneMatch = ifNoneMatch
}

// WithFilter adds the filter to the list files params
func (o *ListFilesParams) WithFilter(filter *string) *ListFilesParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the list files params
func (o *ListFilesParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithPage adds the page to the list files params
func (o *ListFilesParams) WithPage(page *int64) *ListFilesParams {
	o.SetPage(page)
	return o
}

// SetPage adds the page to the list files params
func (o *ListFilesParams) SetPage(page *int64) {
	o.Page = page
}

// WithSize adds the size to the list files params
func (o *ListFilesParams) WithSize(size *int64) *ListFilesParams {
	o.SetSize(size)
	return o
}

// SetSize adds the size to the list files params
func (o *ListFilesParams) SetSize(size *int64) {
	o.Size = size
}

// WithSort adds the sort to the list files params
func (o *ListFilesParams) WithSort(sort *string) *ListFilesParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the list files params
func (o *ListFilesParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *ListFilesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
