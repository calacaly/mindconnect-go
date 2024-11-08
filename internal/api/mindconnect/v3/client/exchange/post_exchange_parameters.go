// Code generated by go-swagger; DO NOT EDIT.

package exchange

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewPostExchangeParams creates a new PostExchangeParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPostExchangeParams() *PostExchangeParams {
	return &PostExchangeParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPostExchangeParamsWithTimeout creates a new PostExchangeParams object
// with the ability to set a timeout on a request.
func NewPostExchangeParamsWithTimeout(timeout time.Duration) *PostExchangeParams {
	return &PostExchangeParams{
		timeout: timeout,
	}
}

// NewPostExchangeParamsWithContext creates a new PostExchangeParams object
// with the ability to set a context for a request.
func NewPostExchangeParamsWithContext(ctx context.Context) *PostExchangeParams {
	return &PostExchangeParams{
		Context: ctx,
	}
}

// NewPostExchangeParamsWithHTTPClient creates a new PostExchangeParams object
// with the ability to set a custom HTTPClient for a request.
func NewPostExchangeParamsWithHTTPClient(client *http.Client) *PostExchangeParams {
	return &PostExchangeParams{
		HTTPClient: client,
	}
}

/*
PostExchangeParams contains all the parameters to send to the API endpoint

	for the post exchange operation.

	Typically these are written to a http.Request.
*/
type PostExchangeParams struct {

	/* Message.

	   Multipart message.

	   Format: binary
	*/
	Message io.ReadCloser

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the post exchange params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostExchangeParams) WithDefaults() *PostExchangeParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the post exchange params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostExchangeParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the post exchange params
func (o *PostExchangeParams) WithTimeout(timeout time.Duration) *PostExchangeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the post exchange params
func (o *PostExchangeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the post exchange params
func (o *PostExchangeParams) WithContext(ctx context.Context) *PostExchangeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the post exchange params
func (o *PostExchangeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the post exchange params
func (o *PostExchangeParams) WithHTTPClient(client *http.Client) *PostExchangeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the post exchange params
func (o *PostExchangeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithMessage adds the message to the post exchange params
func (o *PostExchangeParams) WithMessage(message io.ReadCloser) *PostExchangeParams {
	o.SetMessage(message)
	return o
}

// SetMessage adds the message to the post exchange params
func (o *PostExchangeParams) SetMessage(message io.ReadCloser) {
	o.Message = message
}

// WriteToRequest writes these params to a swagger request
func (o *PostExchangeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Message != nil {
		if err := r.SetBodyParam(o.Message); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
