// Code generated by go-swagger; DO NOT EDIT.

package structure

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

// ListAssetVariablesReader is a Reader for the ListAssetVariables structure.
type ListAssetVariablesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListAssetVariablesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListAssetVariablesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 304:
		result := NewListAssetVariablesNotModified()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 400:
		result := NewListAssetVariablesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewListAssetVariablesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListAssetVariablesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListAssetVariablesNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewListAssetVariablesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 503:
		result := NewListAssetVariablesServiceUnavailable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /assets/{id}/variables] listAssetVariables", response, response.Code())
	}
}

// NewListAssetVariablesOK creates a ListAssetVariablesOK with default headers values
func NewListAssetVariablesOK() *ListAssetVariablesOK {
	return &ListAssetVariablesOK{}
}

/*
ListAssetVariablesOK describes a response with status code 200, with default header values.

Variables of the given asset matched by the given filter criterias
*/
type ListAssetVariablesOK struct {

	/* ETag hash of the resource
	 */
	ETag string

	Payload *models.VariableListResource
}

// IsSuccess returns true when this list asset variables o k response has a 2xx status code
func (o *ListAssetVariablesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list asset variables o k response has a 3xx status code
func (o *ListAssetVariablesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list asset variables o k response has a 4xx status code
func (o *ListAssetVariablesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list asset variables o k response has a 5xx status code
func (o *ListAssetVariablesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list asset variables o k response a status code equal to that given
func (o *ListAssetVariablesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list asset variables o k response
func (o *ListAssetVariablesOK) Code() int {
	return 200
}

func (o *ListAssetVariablesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}/variables][%d] listAssetVariablesOK %s", 200, payload)
}

func (o *ListAssetVariablesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}/variables][%d] listAssetVariablesOK %s", 200, payload)
}

func (o *ListAssetVariablesOK) GetPayload() *models.VariableListResource {
	return o.Payload
}

func (o *ListAssetVariablesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header ETag
	hdrETag := response.GetHeader("ETag")

	if hdrETag != "" {
		o.ETag = hdrETag
	}

	o.Payload = new(models.VariableListResource)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAssetVariablesNotModified creates a ListAssetVariablesNotModified with default headers values
func NewListAssetVariablesNotModified() *ListAssetVariablesNotModified {
	return &ListAssetVariablesNotModified{}
}

/*
ListAssetVariablesNotModified describes a response with status code 304, with default header values.

Resource variables have not been modified
*/
type ListAssetVariablesNotModified struct {
}

// IsSuccess returns true when this list asset variables not modified response has a 2xx status code
func (o *ListAssetVariablesNotModified) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list asset variables not modified response has a 3xx status code
func (o *ListAssetVariablesNotModified) IsRedirect() bool {
	return true
}

// IsClientError returns true when this list asset variables not modified response has a 4xx status code
func (o *ListAssetVariablesNotModified) IsClientError() bool {
	return false
}

// IsServerError returns true when this list asset variables not modified response has a 5xx status code
func (o *ListAssetVariablesNotModified) IsServerError() bool {
	return false
}

// IsCode returns true when this list asset variables not modified response a status code equal to that given
func (o *ListAssetVariablesNotModified) IsCode(code int) bool {
	return code == 304
}

// Code gets the status code for the list asset variables not modified response
func (o *ListAssetVariablesNotModified) Code() int {
	return 304
}

func (o *ListAssetVariablesNotModified) Error() string {
	return fmt.Sprintf("[GET /assets/{id}/variables][%d] listAssetVariablesNotModified", 304)
}

func (o *ListAssetVariablesNotModified) String() string {
	return fmt.Sprintf("[GET /assets/{id}/variables][%d] listAssetVariablesNotModified", 304)
}

func (o *ListAssetVariablesNotModified) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewListAssetVariablesBadRequest creates a ListAssetVariablesBadRequest with default headers values
func NewListAssetVariablesBadRequest() *ListAssetVariablesBadRequest {
	return &ListAssetVariablesBadRequest{}
}

/*
ListAssetVariablesBadRequest describes a response with status code 400, with default header values.

Invalid request
*/
type ListAssetVariablesBadRequest struct {
	Payload *models.Errors
}

// IsSuccess returns true when this list asset variables bad request response has a 2xx status code
func (o *ListAssetVariablesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list asset variables bad request response has a 3xx status code
func (o *ListAssetVariablesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list asset variables bad request response has a 4xx status code
func (o *ListAssetVariablesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this list asset variables bad request response has a 5xx status code
func (o *ListAssetVariablesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this list asset variables bad request response a status code equal to that given
func (o *ListAssetVariablesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the list asset variables bad request response
func (o *ListAssetVariablesBadRequest) Code() int {
	return 400
}

func (o *ListAssetVariablesBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}/variables][%d] listAssetVariablesBadRequest %s", 400, payload)
}

func (o *ListAssetVariablesBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}/variables][%d] listAssetVariablesBadRequest %s", 400, payload)
}

func (o *ListAssetVariablesBadRequest) GetPayload() *models.Errors {
	return o.Payload
}

func (o *ListAssetVariablesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAssetVariablesUnauthorized creates a ListAssetVariablesUnauthorized with default headers values
func NewListAssetVariablesUnauthorized() *ListAssetVariablesUnauthorized {
	return &ListAssetVariablesUnauthorized{}
}

/*
ListAssetVariablesUnauthorized describes a response with status code 401, with default header values.

User is not authenticated
*/
type ListAssetVariablesUnauthorized struct {
	Payload *models.Errors
}

// IsSuccess returns true when this list asset variables unauthorized response has a 2xx status code
func (o *ListAssetVariablesUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list asset variables unauthorized response has a 3xx status code
func (o *ListAssetVariablesUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list asset variables unauthorized response has a 4xx status code
func (o *ListAssetVariablesUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list asset variables unauthorized response has a 5xx status code
func (o *ListAssetVariablesUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list asset variables unauthorized response a status code equal to that given
func (o *ListAssetVariablesUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the list asset variables unauthorized response
func (o *ListAssetVariablesUnauthorized) Code() int {
	return 401
}

func (o *ListAssetVariablesUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}/variables][%d] listAssetVariablesUnauthorized %s", 401, payload)
}

func (o *ListAssetVariablesUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}/variables][%d] listAssetVariablesUnauthorized %s", 401, payload)
}

func (o *ListAssetVariablesUnauthorized) GetPayload() *models.Errors {
	return o.Payload
}

func (o *ListAssetVariablesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAssetVariablesForbidden creates a ListAssetVariablesForbidden with default headers values
func NewListAssetVariablesForbidden() *ListAssetVariablesForbidden {
	return &ListAssetVariablesForbidden{}
}

/*
ListAssetVariablesForbidden describes a response with status code 403, with default header values.

User is not authorized for request
*/
type ListAssetVariablesForbidden struct {
	Payload *models.Errors
}

// IsSuccess returns true when this list asset variables forbidden response has a 2xx status code
func (o *ListAssetVariablesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list asset variables forbidden response has a 3xx status code
func (o *ListAssetVariablesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list asset variables forbidden response has a 4xx status code
func (o *ListAssetVariablesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list asset variables forbidden response has a 5xx status code
func (o *ListAssetVariablesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list asset variables forbidden response a status code equal to that given
func (o *ListAssetVariablesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the list asset variables forbidden response
func (o *ListAssetVariablesForbidden) Code() int {
	return 403
}

func (o *ListAssetVariablesForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}/variables][%d] listAssetVariablesForbidden %s", 403, payload)
}

func (o *ListAssetVariablesForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}/variables][%d] listAssetVariablesForbidden %s", 403, payload)
}

func (o *ListAssetVariablesForbidden) GetPayload() *models.Errors {
	return o.Payload
}

func (o *ListAssetVariablesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAssetVariablesNotFound creates a ListAssetVariablesNotFound with default headers values
func NewListAssetVariablesNotFound() *ListAssetVariablesNotFound {
	return &ListAssetVariablesNotFound{}
}

/*
ListAssetVariablesNotFound describes a response with status code 404, with default header values.

Asset not found
*/
type ListAssetVariablesNotFound struct {
	Payload *models.Errors
}

// IsSuccess returns true when this list asset variables not found response has a 2xx status code
func (o *ListAssetVariablesNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list asset variables not found response has a 3xx status code
func (o *ListAssetVariablesNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list asset variables not found response has a 4xx status code
func (o *ListAssetVariablesNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this list asset variables not found response has a 5xx status code
func (o *ListAssetVariablesNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this list asset variables not found response a status code equal to that given
func (o *ListAssetVariablesNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the list asset variables not found response
func (o *ListAssetVariablesNotFound) Code() int {
	return 404
}

func (o *ListAssetVariablesNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}/variables][%d] listAssetVariablesNotFound %s", 404, payload)
}

func (o *ListAssetVariablesNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}/variables][%d] listAssetVariablesNotFound %s", 404, payload)
}

func (o *ListAssetVariablesNotFound) GetPayload() *models.Errors {
	return o.Payload
}

func (o *ListAssetVariablesNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAssetVariablesInternalServerError creates a ListAssetVariablesInternalServerError with default headers values
func NewListAssetVariablesInternalServerError() *ListAssetVariablesInternalServerError {
	return &ListAssetVariablesInternalServerError{}
}

/*
ListAssetVariablesInternalServerError describes a response with status code 500, with default header values.

Server error, for more information see errorcode and message
*/
type ListAssetVariablesInternalServerError struct {
	Payload *models.Errors
}

// IsSuccess returns true when this list asset variables internal server error response has a 2xx status code
func (o *ListAssetVariablesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list asset variables internal server error response has a 3xx status code
func (o *ListAssetVariablesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list asset variables internal server error response has a 4xx status code
func (o *ListAssetVariablesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this list asset variables internal server error response has a 5xx status code
func (o *ListAssetVariablesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this list asset variables internal server error response a status code equal to that given
func (o *ListAssetVariablesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the list asset variables internal server error response
func (o *ListAssetVariablesInternalServerError) Code() int {
	return 500
}

func (o *ListAssetVariablesInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}/variables][%d] listAssetVariablesInternalServerError %s", 500, payload)
}

func (o *ListAssetVariablesInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}/variables][%d] listAssetVariablesInternalServerError %s", 500, payload)
}

func (o *ListAssetVariablesInternalServerError) GetPayload() *models.Errors {
	return o.Payload
}

func (o *ListAssetVariablesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAssetVariablesServiceUnavailable creates a ListAssetVariablesServiceUnavailable with default headers values
func NewListAssetVariablesServiceUnavailable() *ListAssetVariablesServiceUnavailable {
	return &ListAssetVariablesServiceUnavailable{}
}

/*
ListAssetVariablesServiceUnavailable describes a response with status code 503, with default header values.

Service unavailable, for more information see errorcode and message
*/
type ListAssetVariablesServiceUnavailable struct {
	Payload *models.Errors
}

// IsSuccess returns true when this list asset variables service unavailable response has a 2xx status code
func (o *ListAssetVariablesServiceUnavailable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list asset variables service unavailable response has a 3xx status code
func (o *ListAssetVariablesServiceUnavailable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list asset variables service unavailable response has a 4xx status code
func (o *ListAssetVariablesServiceUnavailable) IsClientError() bool {
	return false
}

// IsServerError returns true when this list asset variables service unavailable response has a 5xx status code
func (o *ListAssetVariablesServiceUnavailable) IsServerError() bool {
	return true
}

// IsCode returns true when this list asset variables service unavailable response a status code equal to that given
func (o *ListAssetVariablesServiceUnavailable) IsCode(code int) bool {
	return code == 503
}

// Code gets the status code for the list asset variables service unavailable response
func (o *ListAssetVariablesServiceUnavailable) Code() int {
	return 503
}

func (o *ListAssetVariablesServiceUnavailable) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}/variables][%d] listAssetVariablesServiceUnavailable %s", 503, payload)
}

func (o *ListAssetVariablesServiceUnavailable) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/{id}/variables][%d] listAssetVariablesServiceUnavailable %s", 503, payload)
}

func (o *ListAssetVariablesServiceUnavailable) GetPayload() *models.Errors {
	return o.Payload
}

func (o *ListAssetVariablesServiceUnavailable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
