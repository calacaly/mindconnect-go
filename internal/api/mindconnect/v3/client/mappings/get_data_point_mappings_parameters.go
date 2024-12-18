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
	"github.com/go-openapi/swag"
)

// NewGetDataPointMappingsParams creates a new GetDataPointMappingsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetDataPointMappingsParams() *GetDataPointMappingsParams {
	return &GetDataPointMappingsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetDataPointMappingsParamsWithTimeout creates a new GetDataPointMappingsParams object
// with the ability to set a timeout on a request.
func NewGetDataPointMappingsParamsWithTimeout(timeout time.Duration) *GetDataPointMappingsParams {
	return &GetDataPointMappingsParams{
		timeout: timeout,
	}
}

// NewGetDataPointMappingsParamsWithContext creates a new GetDataPointMappingsParams object
// with the ability to set a context for a request.
func NewGetDataPointMappingsParamsWithContext(ctx context.Context) *GetDataPointMappingsParams {
	return &GetDataPointMappingsParams{
		Context: ctx,
	}
}

// NewGetDataPointMappingsParamsWithHTTPClient creates a new GetDataPointMappingsParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetDataPointMappingsParamsWithHTTPClient(client *http.Client) *GetDataPointMappingsParams {
	return &GetDataPointMappingsParams{
		HTTPClient: client,
	}
}

/*
GetDataPointMappingsParams contains all the parameters to send to the API endpoint

	for the get data point mappings operation.

	Typically these are written to a http.Request.
*/
type GetDataPointMappingsParams struct {

	/* Filter.

	   Filter as JSON object.
	*/
	Filter *string

	/* Page.

	   The (0-based) index of page.

	   Format: int32
	*/
	Page *int32

	/* Size.

	   The maximum number of elements in a page.

	   Format: int32
	   Default: 20
	*/
	Size *int32

	/* Sort.

	     The order of returned elements.
	Multiple fields could be used separated by commas (e.g. ''field1,field2'').
	Descending order could be requested by appending '',desc'' at the end of parameter.(e.g. ''field1,field2,desc'')'

	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get data point mappings params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetDataPointMappingsParams) WithDefaults() *GetDataPointMappingsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get data point mappings params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetDataPointMappingsParams) SetDefaults() {
	var (
		pageDefault = int32(0)

		sizeDefault = int32(20)
	)

	val := GetDataPointMappingsParams{
		Page: &pageDefault,
		Size: &sizeDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get data point mappings params
func (o *GetDataPointMappingsParams) WithTimeout(timeout time.Duration) *GetDataPointMappingsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get data point mappings params
func (o *GetDataPointMappingsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get data point mappings params
func (o *GetDataPointMappingsParams) WithContext(ctx context.Context) *GetDataPointMappingsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get data point mappings params
func (o *GetDataPointMappingsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get data point mappings params
func (o *GetDataPointMappingsParams) WithHTTPClient(client *http.Client) *GetDataPointMappingsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get data point mappings params
func (o *GetDataPointMappingsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the get data point mappings params
func (o *GetDataPointMappingsParams) WithFilter(filter *string) *GetDataPointMappingsParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the get data point mappings params
func (o *GetDataPointMappingsParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithPage adds the page to the get data point mappings params
func (o *GetDataPointMappingsParams) WithPage(page *int32) *GetDataPointMappingsParams {
	o.SetPage(page)
	return o
}

// SetPage adds the page to the get data point mappings params
func (o *GetDataPointMappingsParams) SetPage(page *int32) {
	o.Page = page
}

// WithSize adds the size to the get data point mappings params
func (o *GetDataPointMappingsParams) WithSize(size *int32) *GetDataPointMappingsParams {
	o.SetSize(size)
	return o
}

// SetSize adds the size to the get data point mappings params
func (o *GetDataPointMappingsParams) SetSize(size *int32) {
	o.Size = size
}

// WithSort adds the sort to the get data point mappings params
func (o *GetDataPointMappingsParams) WithSort(sort *string) *GetDataPointMappingsParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the get data point mappings params
func (o *GetDataPointMappingsParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *GetDataPointMappingsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

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
		var qrPage int32

		if o.Page != nil {
			qrPage = *o.Page
		}
		qPage := swag.FormatInt32(qrPage)
		if qPage != "" {

			if err := r.SetQueryParam("page", qPage); err != nil {
				return err
			}
		}
	}

	if o.Size != nil {

		// query param size
		var qrSize int32

		if o.Size != nil {
			qrSize = *o.Size
		}
		qSize := swag.FormatInt32(qrSize)
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
