// Code generated by go-swagger; DO NOT EDIT.

package diagnostic_activations

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

// NewGetDiagnosticActivationsIDMessagesParams creates a new GetDiagnosticActivationsIDMessagesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetDiagnosticActivationsIDMessagesParams() *GetDiagnosticActivationsIDMessagesParams {
	return &GetDiagnosticActivationsIDMessagesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetDiagnosticActivationsIDMessagesParamsWithTimeout creates a new GetDiagnosticActivationsIDMessagesParams object
// with the ability to set a timeout on a request.
func NewGetDiagnosticActivationsIDMessagesParamsWithTimeout(timeout time.Duration) *GetDiagnosticActivationsIDMessagesParams {
	return &GetDiagnosticActivationsIDMessagesParams{
		timeout: timeout,
	}
}

// NewGetDiagnosticActivationsIDMessagesParamsWithContext creates a new GetDiagnosticActivationsIDMessagesParams object
// with the ability to set a context for a request.
func NewGetDiagnosticActivationsIDMessagesParamsWithContext(ctx context.Context) *GetDiagnosticActivationsIDMessagesParams {
	return &GetDiagnosticActivationsIDMessagesParams{
		Context: ctx,
	}
}

// NewGetDiagnosticActivationsIDMessagesParamsWithHTTPClient creates a new GetDiagnosticActivationsIDMessagesParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetDiagnosticActivationsIDMessagesParamsWithHTTPClient(client *http.Client) *GetDiagnosticActivationsIDMessagesParams {
	return &GetDiagnosticActivationsIDMessagesParams{
		HTTPClient: client,
	}
}

/*
GetDiagnosticActivationsIDMessagesParams contains all the parameters to send to the API endpoint

	for the get diagnostic activations ID messages operation.

	Typically these are written to a http.Request.
*/
type GetDiagnosticActivationsIDMessagesParams struct {

	/* Filter.

	    JSON based filter. Diagnostic messages can be filtered by the following fields
	- `correlationId`
	- `message`
	- `source`
	- `timestamp`
	- `severity`

	*/
	Filter *string

	/* ID.

	   Unique identifier of diagnostic activation resource.
	*/
	ID string

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

// WithDefaults hydrates default values in the get diagnostic activations ID messages params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetDiagnosticActivationsIDMessagesParams) WithDefaults() *GetDiagnosticActivationsIDMessagesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get diagnostic activations ID messages params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetDiagnosticActivationsIDMessagesParams) SetDefaults() {
	var (
		pageDefault = int32(0)

		sizeDefault = int32(20)
	)

	val := GetDiagnosticActivationsIDMessagesParams{
		Page: &pageDefault,
		Size: &sizeDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get diagnostic activations ID messages params
func (o *GetDiagnosticActivationsIDMessagesParams) WithTimeout(timeout time.Duration) *GetDiagnosticActivationsIDMessagesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get diagnostic activations ID messages params
func (o *GetDiagnosticActivationsIDMessagesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get diagnostic activations ID messages params
func (o *GetDiagnosticActivationsIDMessagesParams) WithContext(ctx context.Context) *GetDiagnosticActivationsIDMessagesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get diagnostic activations ID messages params
func (o *GetDiagnosticActivationsIDMessagesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get diagnostic activations ID messages params
func (o *GetDiagnosticActivationsIDMessagesParams) WithHTTPClient(client *http.Client) *GetDiagnosticActivationsIDMessagesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get diagnostic activations ID messages params
func (o *GetDiagnosticActivationsIDMessagesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the get diagnostic activations ID messages params
func (o *GetDiagnosticActivationsIDMessagesParams) WithFilter(filter *string) *GetDiagnosticActivationsIDMessagesParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the get diagnostic activations ID messages params
func (o *GetDiagnosticActivationsIDMessagesParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithID adds the id to the get diagnostic activations ID messages params
func (o *GetDiagnosticActivationsIDMessagesParams) WithID(id string) *GetDiagnosticActivationsIDMessagesParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the get diagnostic activations ID messages params
func (o *GetDiagnosticActivationsIDMessagesParams) SetID(id string) {
	o.ID = id
}

// WithPage adds the page to the get diagnostic activations ID messages params
func (o *GetDiagnosticActivationsIDMessagesParams) WithPage(page *int32) *GetDiagnosticActivationsIDMessagesParams {
	o.SetPage(page)
	return o
}

// SetPage adds the page to the get diagnostic activations ID messages params
func (o *GetDiagnosticActivationsIDMessagesParams) SetPage(page *int32) {
	o.Page = page
}

// WithSize adds the size to the get diagnostic activations ID messages params
func (o *GetDiagnosticActivationsIDMessagesParams) WithSize(size *int32) *GetDiagnosticActivationsIDMessagesParams {
	o.SetSize(size)
	return o
}

// SetSize adds the size to the get diagnostic activations ID messages params
func (o *GetDiagnosticActivationsIDMessagesParams) SetSize(size *int32) {
	o.Size = size
}

// WithSort adds the sort to the get diagnostic activations ID messages params
func (o *GetDiagnosticActivationsIDMessagesParams) WithSort(sort *string) *GetDiagnosticActivationsIDMessagesParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the get diagnostic activations ID messages params
func (o *GetDiagnosticActivationsIDMessagesParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *GetDiagnosticActivationsIDMessagesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	// path param id
	if err := r.SetPathParam("id", o.ID); err != nil {
		return err
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
