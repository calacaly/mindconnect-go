// Code generated by go-swagger; DO NOT EDIT.

package assetmodellock

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

// GetAssetModelLockReader is a Reader for the GetAssetModelLock structure.
type GetAssetModelLockReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAssetModelLockReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAssetModelLockOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetAssetModelLockUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetAssetModelLockForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetAssetModelLockTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetAssetModelLockInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /model/lock] getAssetModelLock", response, response.Code())
	}
}

// NewGetAssetModelLockOK creates a GetAssetModelLockOK with default headers values
func NewGetAssetModelLockOK() *GetAssetModelLockOK {
	return &GetAssetModelLockOK{}
}

/*
GetAssetModelLockOK describes a response with status code 200, with default header values.

Returns lock state of an asset model and associated jobs.
*/
type GetAssetModelLockOK struct {
	Payload *models.AssetModelLock
}

// IsSuccess returns true when this get asset model lock o k response has a 2xx status code
func (o *GetAssetModelLockOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get asset model lock o k response has a 3xx status code
func (o *GetAssetModelLockOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get asset model lock o k response has a 4xx status code
func (o *GetAssetModelLockOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get asset model lock o k response has a 5xx status code
func (o *GetAssetModelLockOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get asset model lock o k response a status code equal to that given
func (o *GetAssetModelLockOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get asset model lock o k response
func (o *GetAssetModelLockOK) Code() int {
	return 200
}

func (o *GetAssetModelLockOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /model/lock][%d] getAssetModelLockOK %s", 200, payload)
}

func (o *GetAssetModelLockOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /model/lock][%d] getAssetModelLockOK %s", 200, payload)
}

func (o *GetAssetModelLockOK) GetPayload() *models.AssetModelLock {
	return o.Payload
}

func (o *GetAssetModelLockOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AssetModelLock)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAssetModelLockUnauthorized creates a GetAssetModelLockUnauthorized with default headers values
func NewGetAssetModelLockUnauthorized() *GetAssetModelLockUnauthorized {
	return &GetAssetModelLockUnauthorized{}
}

/*
GetAssetModelLockUnauthorized describes a response with status code 401, with default header values.

User is not authenticated
*/
type GetAssetModelLockUnauthorized struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get asset model lock unauthorized response has a 2xx status code
func (o *GetAssetModelLockUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get asset model lock unauthorized response has a 3xx status code
func (o *GetAssetModelLockUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get asset model lock unauthorized response has a 4xx status code
func (o *GetAssetModelLockUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get asset model lock unauthorized response has a 5xx status code
func (o *GetAssetModelLockUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get asset model lock unauthorized response a status code equal to that given
func (o *GetAssetModelLockUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get asset model lock unauthorized response
func (o *GetAssetModelLockUnauthorized) Code() int {
	return 401
}

func (o *GetAssetModelLockUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /model/lock][%d] getAssetModelLockUnauthorized %s", 401, payload)
}

func (o *GetAssetModelLockUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /model/lock][%d] getAssetModelLockUnauthorized %s", 401, payload)
}

func (o *GetAssetModelLockUnauthorized) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetAssetModelLockUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAssetModelLockForbidden creates a GetAssetModelLockForbidden with default headers values
func NewGetAssetModelLockForbidden() *GetAssetModelLockForbidden {
	return &GetAssetModelLockForbidden{}
}

/*
GetAssetModelLockForbidden describes a response with status code 403, with default header values.

User is not authorized for request
*/
type GetAssetModelLockForbidden struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get asset model lock forbidden response has a 2xx status code
func (o *GetAssetModelLockForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get asset model lock forbidden response has a 3xx status code
func (o *GetAssetModelLockForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get asset model lock forbidden response has a 4xx status code
func (o *GetAssetModelLockForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get asset model lock forbidden response has a 5xx status code
func (o *GetAssetModelLockForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get asset model lock forbidden response a status code equal to that given
func (o *GetAssetModelLockForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get asset model lock forbidden response
func (o *GetAssetModelLockForbidden) Code() int {
	return 403
}

func (o *GetAssetModelLockForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /model/lock][%d] getAssetModelLockForbidden %s", 403, payload)
}

func (o *GetAssetModelLockForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /model/lock][%d] getAssetModelLockForbidden %s", 403, payload)
}

func (o *GetAssetModelLockForbidden) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetAssetModelLockForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAssetModelLockTooManyRequests creates a GetAssetModelLockTooManyRequests with default headers values
func NewGetAssetModelLockTooManyRequests() *GetAssetModelLockTooManyRequests {
	return &GetAssetModelLockTooManyRequests{}
}

/*
GetAssetModelLockTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetAssetModelLockTooManyRequests struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get asset model lock too many requests response has a 2xx status code
func (o *GetAssetModelLockTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get asset model lock too many requests response has a 3xx status code
func (o *GetAssetModelLockTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get asset model lock too many requests response has a 4xx status code
func (o *GetAssetModelLockTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get asset model lock too many requests response has a 5xx status code
func (o *GetAssetModelLockTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get asset model lock too many requests response a status code equal to that given
func (o *GetAssetModelLockTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get asset model lock too many requests response
func (o *GetAssetModelLockTooManyRequests) Code() int {
	return 429
}

func (o *GetAssetModelLockTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /model/lock][%d] getAssetModelLockTooManyRequests %s", 429, payload)
}

func (o *GetAssetModelLockTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /model/lock][%d] getAssetModelLockTooManyRequests %s", 429, payload)
}

func (o *GetAssetModelLockTooManyRequests) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetAssetModelLockTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAssetModelLockInternalServerError creates a GetAssetModelLockInternalServerError with default headers values
func NewGetAssetModelLockInternalServerError() *GetAssetModelLockInternalServerError {
	return &GetAssetModelLockInternalServerError{}
}

/*
GetAssetModelLockInternalServerError describes a response with status code 500, with default header values.

Server error, for more information see errorcode and message
*/
type GetAssetModelLockInternalServerError struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get asset model lock internal server error response has a 2xx status code
func (o *GetAssetModelLockInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get asset model lock internal server error response has a 3xx status code
func (o *GetAssetModelLockInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get asset model lock internal server error response has a 4xx status code
func (o *GetAssetModelLockInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get asset model lock internal server error response has a 5xx status code
func (o *GetAssetModelLockInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get asset model lock internal server error response a status code equal to that given
func (o *GetAssetModelLockInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get asset model lock internal server error response
func (o *GetAssetModelLockInternalServerError) Code() int {
	return 500
}

func (o *GetAssetModelLockInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /model/lock][%d] getAssetModelLockInternalServerError %s", 500, payload)
}

func (o *GetAssetModelLockInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /model/lock][%d] getAssetModelLockInternalServerError %s", 500, payload)
}

func (o *GetAssetModelLockInternalServerError) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetAssetModelLockInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
