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
)

// NewReplaceFileParams creates a new ReplaceFileParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewReplaceFileParams() *ReplaceFileParams {
	return &ReplaceFileParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewReplaceFileParamsWithTimeout creates a new ReplaceFileParams object
// with the ability to set a timeout on a request.
func NewReplaceFileParamsWithTimeout(timeout time.Duration) *ReplaceFileParams {
	return &ReplaceFileParams{
		timeout: timeout,
	}
}

// NewReplaceFileParamsWithContext creates a new ReplaceFileParams object
// with the ability to set a context for a request.
func NewReplaceFileParamsWithContext(ctx context.Context) *ReplaceFileParams {
	return &ReplaceFileParams{
		Context: ctx,
	}
}

// NewReplaceFileParamsWithHTTPClient creates a new ReplaceFileParams object
// with the ability to set a custom HTTPClient for a request.
func NewReplaceFileParamsWithHTTPClient(client *http.Client) *ReplaceFileParams {
	return &ReplaceFileParams{
		HTTPClient: client,
	}
}

/*
ReplaceFileParams contains all the parameters to send to the API endpoint

	for the replace file operation.

	Typically these are written to a http.Request.
*/
type ReplaceFileParams struct {

	/* IfMatch.

	   Last known version to facilitate optimistic locking
	*/
	IfMatch string

	/* Description.

	   The description of the file
	*/
	Description *string

	/* File.

	   The file to upload. The file size cannot be more than 5 MB.

	   Format: binary
	*/
	File runtime.NamedReadCloser

	/* FileID.

	   Unique identifier of the file.
	*/
	FileID string

	/* Name.

	   The name of the file
	*/
	Name string

	/* Scope.

	   The scope of the file

	   Default: "private"
	*/
	Scope string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the replace file params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ReplaceFileParams) WithDefaults() *ReplaceFileParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the replace file params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ReplaceFileParams) SetDefaults() {
	var (
		scopeDefault = string("private")
	)

	val := ReplaceFileParams{
		Scope: scopeDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the replace file params
func (o *ReplaceFileParams) WithTimeout(timeout time.Duration) *ReplaceFileParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the replace file params
func (o *ReplaceFileParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the replace file params
func (o *ReplaceFileParams) WithContext(ctx context.Context) *ReplaceFileParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the replace file params
func (o *ReplaceFileParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the replace file params
func (o *ReplaceFileParams) WithHTTPClient(client *http.Client) *ReplaceFileParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the replace file params
func (o *ReplaceFileParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the replace file params
func (o *ReplaceFileParams) WithIfMatch(ifMatch string) *ReplaceFileParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the replace file params
func (o *ReplaceFileParams) SetIfMatch(ifMatch string) {
	o.IfMatch = ifMatch
}

// WithDescription adds the description to the replace file params
func (o *ReplaceFileParams) WithDescription(description *string) *ReplaceFileParams {
	o.SetDescription(description)
	return o
}

// SetDescription adds the description to the replace file params
func (o *ReplaceFileParams) SetDescription(description *string) {
	o.Description = description
}

// WithFile adds the file to the replace file params
func (o *ReplaceFileParams) WithFile(file runtime.NamedReadCloser) *ReplaceFileParams {
	o.SetFile(file)
	return o
}

// SetFile adds the file to the replace file params
func (o *ReplaceFileParams) SetFile(file runtime.NamedReadCloser) {
	o.File = file
}

// WithFileID adds the fileID to the replace file params
func (o *ReplaceFileParams) WithFileID(fileID string) *ReplaceFileParams {
	o.SetFileID(fileID)
	return o
}

// SetFileID adds the fileId to the replace file params
func (o *ReplaceFileParams) SetFileID(fileID string) {
	o.FileID = fileID
}

// WithName adds the name to the replace file params
func (o *ReplaceFileParams) WithName(name string) *ReplaceFileParams {
	o.SetName(name)
	return o
}

// SetName adds the name to the replace file params
func (o *ReplaceFileParams) SetName(name string) {
	o.Name = name
}

// WithScope adds the scope to the replace file params
func (o *ReplaceFileParams) WithScope(scope string) *ReplaceFileParams {
	o.SetScope(scope)
	return o
}

// SetScope adds the scope to the replace file params
func (o *ReplaceFileParams) SetScope(scope string) {
	o.Scope = scope
}

// WriteToRequest writes these params to a swagger request
func (o *ReplaceFileParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// header param If-Match
	if err := r.SetHeaderParam("If-Match", o.IfMatch); err != nil {
		return err
	}

	if o.Description != nil {

		// form param description
		var frDescription string
		if o.Description != nil {
			frDescription = *o.Description
		}
		fDescription := frDescription
		if fDescription != "" {
			if err := r.SetFormParam("description", fDescription); err != nil {
				return err
			}
		}
	}
	// form file param file
	if err := r.SetFileParam("file", o.File); err != nil {
		return err
	}

	// path param fileId
	if err := r.SetPathParam("fileId", o.FileID); err != nil {
		return err
	}

	// form param name
	frName := o.Name
	fName := frName
	if fName != "" {
		if err := r.SetFormParam("name", fName); err != nil {
			return err
		}
	}

	// form param scope
	frScope := o.Scope
	fScope := frScope
	if fScope != "" {
		if err := r.SetFormParam("scope", fScope); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}