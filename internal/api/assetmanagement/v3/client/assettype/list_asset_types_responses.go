// Code generated by go-swagger; DO NOT EDIT.

package assettype

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

// ListAssetTypesReader is a Reader for the ListAssetTypes structure.
type ListAssetTypesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListAssetTypesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListAssetTypesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 304:
		result := NewListAssetTypesNotModified()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 400:
		result := NewListAssetTypesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewListAssetTypesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListAssetTypesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewListAssetTypesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /assettypes] listAssetTypes", response, response.Code())
	}
}

// NewListAssetTypesOK creates a ListAssetTypesOK with default headers values
func NewListAssetTypesOK() *ListAssetTypesOK {
	return &ListAssetTypesOK{}
}

/*
ListAssetTypesOK describes a response with status code 200, with default header values.

Array of asset types matched the tenant scope and filter criterias
*/
type ListAssetTypesOK struct {

	/* Shallow ETag of the resource
	 */
	ETag string

	Payload *models.AssetTypeListResource
}

// IsSuccess returns true when this list asset types o k response has a 2xx status code
func (o *ListAssetTypesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list asset types o k response has a 3xx status code
func (o *ListAssetTypesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list asset types o k response has a 4xx status code
func (o *ListAssetTypesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list asset types o k response has a 5xx status code
func (o *ListAssetTypesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list asset types o k response a status code equal to that given
func (o *ListAssetTypesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list asset types o k response
func (o *ListAssetTypesOK) Code() int {
	return 200
}

func (o *ListAssetTypesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes][%d] listAssetTypesOK %s", 200, payload)
}

func (o *ListAssetTypesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes][%d] listAssetTypesOK %s", 200, payload)
}

func (o *ListAssetTypesOK) GetPayload() *models.AssetTypeListResource {
	return o.Payload
}

func (o *ListAssetTypesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header ETag
	hdrETag := response.GetHeader("ETag")

	if hdrETag != "" {
		o.ETag = hdrETag
	}

	o.Payload = new(models.AssetTypeListResource)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAssetTypesNotModified creates a ListAssetTypesNotModified with default headers values
func NewListAssetTypesNotModified() *ListAssetTypesNotModified {
	return &ListAssetTypesNotModified{}
}

/*
ListAssetTypesNotModified describes a response with status code 304, with default header values.

Asset-types page not changed
*/
type ListAssetTypesNotModified struct {
}

// IsSuccess returns true when this list asset types not modified response has a 2xx status code
func (o *ListAssetTypesNotModified) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list asset types not modified response has a 3xx status code
func (o *ListAssetTypesNotModified) IsRedirect() bool {
	return true
}

// IsClientError returns true when this list asset types not modified response has a 4xx status code
func (o *ListAssetTypesNotModified) IsClientError() bool {
	return false
}

// IsServerError returns true when this list asset types not modified response has a 5xx status code
func (o *ListAssetTypesNotModified) IsServerError() bool {
	return false
}

// IsCode returns true when this list asset types not modified response a status code equal to that given
func (o *ListAssetTypesNotModified) IsCode(code int) bool {
	return code == 304
}

// Code gets the status code for the list asset types not modified response
func (o *ListAssetTypesNotModified) Code() int {
	return 304
}

func (o *ListAssetTypesNotModified) Error() string {
	return fmt.Sprintf("[GET /assettypes][%d] listAssetTypesNotModified", 304)
}

func (o *ListAssetTypesNotModified) String() string {
	return fmt.Sprintf("[GET /assettypes][%d] listAssetTypesNotModified", 304)
}

func (o *ListAssetTypesNotModified) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewListAssetTypesBadRequest creates a ListAssetTypesBadRequest with default headers values
func NewListAssetTypesBadRequest() *ListAssetTypesBadRequest {
	return &ListAssetTypesBadRequest{}
}

/*
ListAssetTypesBadRequest describes a response with status code 400, with default header values.

Invalid request
*/
type ListAssetTypesBadRequest struct {
	Payload *models.Errors
}

// IsSuccess returns true when this list asset types bad request response has a 2xx status code
func (o *ListAssetTypesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list asset types bad request response has a 3xx status code
func (o *ListAssetTypesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list asset types bad request response has a 4xx status code
func (o *ListAssetTypesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this list asset types bad request response has a 5xx status code
func (o *ListAssetTypesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this list asset types bad request response a status code equal to that given
func (o *ListAssetTypesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the list asset types bad request response
func (o *ListAssetTypesBadRequest) Code() int {
	return 400
}

func (o *ListAssetTypesBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes][%d] listAssetTypesBadRequest %s", 400, payload)
}

func (o *ListAssetTypesBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes][%d] listAssetTypesBadRequest %s", 400, payload)
}

func (o *ListAssetTypesBadRequest) GetPayload() *models.Errors {
	return o.Payload
}

func (o *ListAssetTypesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAssetTypesUnauthorized creates a ListAssetTypesUnauthorized with default headers values
func NewListAssetTypesUnauthorized() *ListAssetTypesUnauthorized {
	return &ListAssetTypesUnauthorized{}
}

/*
ListAssetTypesUnauthorized describes a response with status code 401, with default header values.

User is not authenticated
*/
type ListAssetTypesUnauthorized struct {
	Payload *models.Errors
}

// IsSuccess returns true when this list asset types unauthorized response has a 2xx status code
func (o *ListAssetTypesUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list asset types unauthorized response has a 3xx status code
func (o *ListAssetTypesUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list asset types unauthorized response has a 4xx status code
func (o *ListAssetTypesUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list asset types unauthorized response has a 5xx status code
func (o *ListAssetTypesUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list asset types unauthorized response a status code equal to that given
func (o *ListAssetTypesUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the list asset types unauthorized response
func (o *ListAssetTypesUnauthorized) Code() int {
	return 401
}

func (o *ListAssetTypesUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes][%d] listAssetTypesUnauthorized %s", 401, payload)
}

func (o *ListAssetTypesUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes][%d] listAssetTypesUnauthorized %s", 401, payload)
}

func (o *ListAssetTypesUnauthorized) GetPayload() *models.Errors {
	return o.Payload
}

func (o *ListAssetTypesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAssetTypesForbidden creates a ListAssetTypesForbidden with default headers values
func NewListAssetTypesForbidden() *ListAssetTypesForbidden {
	return &ListAssetTypesForbidden{}
}

/*
ListAssetTypesForbidden describes a response with status code 403, with default header values.

User is not authorized for request
*/
type ListAssetTypesForbidden struct {
	Payload *models.Errors
}

// IsSuccess returns true when this list asset types forbidden response has a 2xx status code
func (o *ListAssetTypesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list asset types forbidden response has a 3xx status code
func (o *ListAssetTypesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list asset types forbidden response has a 4xx status code
func (o *ListAssetTypesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list asset types forbidden response has a 5xx status code
func (o *ListAssetTypesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list asset types forbidden response a status code equal to that given
func (o *ListAssetTypesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the list asset types forbidden response
func (o *ListAssetTypesForbidden) Code() int {
	return 403
}

func (o *ListAssetTypesForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes][%d] listAssetTypesForbidden %s", 403, payload)
}

func (o *ListAssetTypesForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes][%d] listAssetTypesForbidden %s", 403, payload)
}

func (o *ListAssetTypesForbidden) GetPayload() *models.Errors {
	return o.Payload
}

func (o *ListAssetTypesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAssetTypesInternalServerError creates a ListAssetTypesInternalServerError with default headers values
func NewListAssetTypesInternalServerError() *ListAssetTypesInternalServerError {
	return &ListAssetTypesInternalServerError{}
}

/*
ListAssetTypesInternalServerError describes a response with status code 500, with default header values.

Server error, for more information see errorcode and message
*/
type ListAssetTypesInternalServerError struct {
	Payload *models.Errors
}

// IsSuccess returns true when this list asset types internal server error response has a 2xx status code
func (o *ListAssetTypesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list asset types internal server error response has a 3xx status code
func (o *ListAssetTypesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list asset types internal server error response has a 4xx status code
func (o *ListAssetTypesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this list asset types internal server error response has a 5xx status code
func (o *ListAssetTypesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this list asset types internal server error response a status code equal to that given
func (o *ListAssetTypesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the list asset types internal server error response
func (o *ListAssetTypesInternalServerError) Code() int {
	return 500
}

func (o *ListAssetTypesInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes][%d] listAssetTypesInternalServerError %s", 500, payload)
}

func (o *ListAssetTypesInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes][%d] listAssetTypesInternalServerError %s", 500, payload)
}

func (o *ListAssetTypesInternalServerError) GetPayload() *models.Errors {
	return o.Payload
}

func (o *ListAssetTypesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
