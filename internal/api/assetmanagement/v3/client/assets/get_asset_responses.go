// Code generated by go-swagger; DO NOT EDIT.

package assets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/calacaly/mindconnect-go/internal/api/assetmanagement/v3/models"
)

// GetAssetReader is a Reader for the GetAsset structure.
type GetAssetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAssetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAssetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 304:
		result := NewGetAssetNotModified()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetAssetUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetAssetForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetAssetNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetAssetInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 503:
		result := NewGetAssetServiceUnavailable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /assets/{id}] getAsset", response, response.Code())
	}
}

// NewGetAssetOK creates a GetAssetOK with default headers values
func NewGetAssetOK() *GetAssetOK {
	return &GetAssetOK{}
}

/*
GetAssetOK describes a response with status code 200, with default header values.

Returns an asset with its static properties.
*/
type GetAssetOK struct {

	/* ETag hash of the resource
	 */
	ETag string

	Payload *models.AssetResourceWithHierarchyPath
}

// IsSuccess returns true when this get asset o k response has a 2xx status code
func (o *GetAssetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get asset o k response has a 3xx status code
func (o *GetAssetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get asset o k response has a 4xx status code
func (o *GetAssetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get asset o k response has a 5xx status code
func (o *GetAssetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get asset o k response a status code equal to that given
func (o *GetAssetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get asset o k response
func (o *GetAssetOK) Code() int {
	return 200
}

func (o *GetAssetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}][%d] getAssetOK %s", 200, payload)
}

func (o *GetAssetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}][%d] getAssetOK %s", 200, payload)
}

func (o *GetAssetOK) GetPayload() *models.AssetResourceWithHierarchyPath {
	return o.Payload
}

func (o *GetAssetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header ETag
	hdrETag := response.GetHeader("ETag")

	if hdrETag != "" {
		o.ETag = hdrETag
	}

	o.Payload = new(models.AssetResourceWithHierarchyPath)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAssetNotModified creates a GetAssetNotModified with default headers values
func NewGetAssetNotModified() *GetAssetNotModified {
	return &GetAssetNotModified{}
}

/*
GetAssetNotModified describes a response with status code 304, with default header values.

Resource asset is not modified
*/
type GetAssetNotModified struct {
}

// IsSuccess returns true when this get asset not modified response has a 2xx status code
func (o *GetAssetNotModified) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get asset not modified response has a 3xx status code
func (o *GetAssetNotModified) IsRedirect() bool {
	return true
}

// IsClientError returns true when this get asset not modified response has a 4xx status code
func (o *GetAssetNotModified) IsClientError() bool {
	return false
}

// IsServerError returns true when this get asset not modified response has a 5xx status code
func (o *GetAssetNotModified) IsServerError() bool {
	return false
}

// IsCode returns true when this get asset not modified response a status code equal to that given
func (o *GetAssetNotModified) IsCode(code int) bool {
	return code == 304
}

// Code gets the status code for the get asset not modified response
func (o *GetAssetNotModified) Code() int {
	return 304
}

func (o *GetAssetNotModified) Error() string {
	return fmt.Sprintf("[GET /assets/{id}][%d] getAssetNotModified", 304)
}

func (o *GetAssetNotModified) String() string {
	return fmt.Sprintf("[GET /assets/{id}][%d] getAssetNotModified", 304)
}

func (o *GetAssetNotModified) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetAssetUnauthorized creates a GetAssetUnauthorized with default headers values
func NewGetAssetUnauthorized() *GetAssetUnauthorized {
	return &GetAssetUnauthorized{}
}

/*
GetAssetUnauthorized describes a response with status code 401, with default header values.

User is not authenticated
*/
type GetAssetUnauthorized struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get asset unauthorized response has a 2xx status code
func (o *GetAssetUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get asset unauthorized response has a 3xx status code
func (o *GetAssetUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get asset unauthorized response has a 4xx status code
func (o *GetAssetUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get asset unauthorized response has a 5xx status code
func (o *GetAssetUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get asset unauthorized response a status code equal to that given
func (o *GetAssetUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get asset unauthorized response
func (o *GetAssetUnauthorized) Code() int {
	return 401
}

func (o *GetAssetUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}][%d] getAssetUnauthorized %s", 401, payload)
}

func (o *GetAssetUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}][%d] getAssetUnauthorized %s", 401, payload)
}

func (o *GetAssetUnauthorized) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetAssetUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAssetForbidden creates a GetAssetForbidden with default headers values
func NewGetAssetForbidden() *GetAssetForbidden {
	return &GetAssetForbidden{}
}

/*
GetAssetForbidden describes a response with status code 403, with default header values.

User is not authorized for request
*/
type GetAssetForbidden struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get asset forbidden response has a 2xx status code
func (o *GetAssetForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get asset forbidden response has a 3xx status code
func (o *GetAssetForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get asset forbidden response has a 4xx status code
func (o *GetAssetForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get asset forbidden response has a 5xx status code
func (o *GetAssetForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get asset forbidden response a status code equal to that given
func (o *GetAssetForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get asset forbidden response
func (o *GetAssetForbidden) Code() int {
	return 403
}

func (o *GetAssetForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}][%d] getAssetForbidden %s", 403, payload)
}

func (o *GetAssetForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}][%d] getAssetForbidden %s", 403, payload)
}

func (o *GetAssetForbidden) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetAssetForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAssetNotFound creates a GetAssetNotFound with default headers values
func NewGetAssetNotFound() *GetAssetNotFound {
	return &GetAssetNotFound{}
}

/*
GetAssetNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetAssetNotFound struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get asset not found response has a 2xx status code
func (o *GetAssetNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get asset not found response has a 3xx status code
func (o *GetAssetNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get asset not found response has a 4xx status code
func (o *GetAssetNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get asset not found response has a 5xx status code
func (o *GetAssetNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get asset not found response a status code equal to that given
func (o *GetAssetNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get asset not found response
func (o *GetAssetNotFound) Code() int {
	return 404
}

func (o *GetAssetNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}][%d] getAssetNotFound %s", 404, payload)
}

func (o *GetAssetNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}][%d] getAssetNotFound %s", 404, payload)
}

func (o *GetAssetNotFound) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetAssetNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAssetInternalServerError creates a GetAssetInternalServerError with default headers values
func NewGetAssetInternalServerError() *GetAssetInternalServerError {
	return &GetAssetInternalServerError{}
}

/*
GetAssetInternalServerError describes a response with status code 500, with default header values.

Server error, for more information see errorcode and message
*/
type GetAssetInternalServerError struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get asset internal server error response has a 2xx status code
func (o *GetAssetInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get asset internal server error response has a 3xx status code
func (o *GetAssetInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get asset internal server error response has a 4xx status code
func (o *GetAssetInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get asset internal server error response has a 5xx status code
func (o *GetAssetInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get asset internal server error response a status code equal to that given
func (o *GetAssetInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get asset internal server error response
func (o *GetAssetInternalServerError) Code() int {
	return 500
}

func (o *GetAssetInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}][%d] getAssetInternalServerError %s", 500, payload)
}

func (o *GetAssetInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}][%d] getAssetInternalServerError %s", 500, payload)
}

func (o *GetAssetInternalServerError) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetAssetInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAssetServiceUnavailable creates a GetAssetServiceUnavailable with default headers values
func NewGetAssetServiceUnavailable() *GetAssetServiceUnavailable {
	return &GetAssetServiceUnavailable{}
}

/*
GetAssetServiceUnavailable describes a response with status code 503, with default header values.

Service unavailable, for more information see errorcode and message
*/
type GetAssetServiceUnavailable struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get asset service unavailable response has a 2xx status code
func (o *GetAssetServiceUnavailable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get asset service unavailable response has a 3xx status code
func (o *GetAssetServiceUnavailable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get asset service unavailable response has a 4xx status code
func (o *GetAssetServiceUnavailable) IsClientError() bool {
	return false
}

// IsServerError returns true when this get asset service unavailable response has a 5xx status code
func (o *GetAssetServiceUnavailable) IsServerError() bool {
	return true
}

// IsCode returns true when this get asset service unavailable response a status code equal to that given
func (o *GetAssetServiceUnavailable) IsCode(code int) bool {
	return code == 503
}

// Code gets the status code for the get asset service unavailable response
func (o *GetAssetServiceUnavailable) Code() int {
	return 503
}

func (o *GetAssetServiceUnavailable) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}][%d] getAssetServiceUnavailable %s", 503, payload)
}

func (o *GetAssetServiceUnavailable) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}][%d] getAssetServiceUnavailable %s", 503, payload)
}

func (o *GetAssetServiceUnavailable) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetAssetServiceUnavailable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
