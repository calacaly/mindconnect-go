// Code generated by go-swagger; DO NOT EDIT.

package assets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/calacaly/mindconnect-go/internal/api/assetmanagement/v3/models"
)

// AddAssetReader is a Reader for the AddAsset structure.
type AddAssetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AddAssetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewAddAssetCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewAddAssetBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewAddAssetUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewAddAssetForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewAddAssetInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 503:
		result := NewAddAssetServiceUnavailable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /assets] addAsset", response, response.Code())
	}
}

// NewAddAssetCreated creates a AddAssetCreated with default headers values
func NewAddAssetCreated() *AddAssetCreated {
	return &AddAssetCreated{}
}

/*
AddAssetCreated describes a response with status code 201, with default header values.

The asset is created
*/
type AddAssetCreated struct {

	/* URL of the created resource

	   Format: uri
	*/
	Location strfmt.URI

	Payload *models.AssetResourceWithHierarchyPath
}

// IsSuccess returns true when this add asset created response has a 2xx status code
func (o *AddAssetCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this add asset created response has a 3xx status code
func (o *AddAssetCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this add asset created response has a 4xx status code
func (o *AddAssetCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this add asset created response has a 5xx status code
func (o *AddAssetCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this add asset created response a status code equal to that given
func (o *AddAssetCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the add asset created response
func (o *AddAssetCreated) Code() int {
	return 201
}

func (o *AddAssetCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /assets][%d] addAssetCreated %s", 201, payload)
}

func (o *AddAssetCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /assets][%d] addAssetCreated %s", 201, payload)
}

func (o *AddAssetCreated) GetPayload() *models.AssetResourceWithHierarchyPath {
	return o.Payload
}

func (o *AddAssetCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header Location
	hdrLocation := response.GetHeader("Location")

	if hdrLocation != "" {
		vallocation, err := formats.Parse("uri", hdrLocation)
		if err != nil {
			return errors.InvalidType("Location", "header", "strfmt.URI", hdrLocation)
		}
		o.Location = *(vallocation.(*strfmt.URI))
	}

	o.Payload = new(models.AssetResourceWithHierarchyPath)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAddAssetBadRequest creates a AddAssetBadRequest with default headers values
func NewAddAssetBadRequest() *AddAssetBadRequest {
	return &AddAssetBadRequest{}
}

/*
AddAssetBadRequest describes a response with status code 400, with default header values.

Invalid request
*/
type AddAssetBadRequest struct {
	Payload *models.Errors
}

// IsSuccess returns true when this add asset bad request response has a 2xx status code
func (o *AddAssetBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this add asset bad request response has a 3xx status code
func (o *AddAssetBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this add asset bad request response has a 4xx status code
func (o *AddAssetBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this add asset bad request response has a 5xx status code
func (o *AddAssetBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this add asset bad request response a status code equal to that given
func (o *AddAssetBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the add asset bad request response
func (o *AddAssetBadRequest) Code() int {
	return 400
}

func (o *AddAssetBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /assets][%d] addAssetBadRequest %s", 400, payload)
}

func (o *AddAssetBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /assets][%d] addAssetBadRequest %s", 400, payload)
}

func (o *AddAssetBadRequest) GetPayload() *models.Errors {
	return o.Payload
}

func (o *AddAssetBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAddAssetUnauthorized creates a AddAssetUnauthorized with default headers values
func NewAddAssetUnauthorized() *AddAssetUnauthorized {
	return &AddAssetUnauthorized{}
}

/*
AddAssetUnauthorized describes a response with status code 401, with default header values.

User is not authenticated
*/
type AddAssetUnauthorized struct {
	Payload *models.Errors
}

// IsSuccess returns true when this add asset unauthorized response has a 2xx status code
func (o *AddAssetUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this add asset unauthorized response has a 3xx status code
func (o *AddAssetUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this add asset unauthorized response has a 4xx status code
func (o *AddAssetUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this add asset unauthorized response has a 5xx status code
func (o *AddAssetUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this add asset unauthorized response a status code equal to that given
func (o *AddAssetUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the add asset unauthorized response
func (o *AddAssetUnauthorized) Code() int {
	return 401
}

func (o *AddAssetUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /assets][%d] addAssetUnauthorized %s", 401, payload)
}

func (o *AddAssetUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /assets][%d] addAssetUnauthorized %s", 401, payload)
}

func (o *AddAssetUnauthorized) GetPayload() *models.Errors {
	return o.Payload
}

func (o *AddAssetUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAddAssetForbidden creates a AddAssetForbidden with default headers values
func NewAddAssetForbidden() *AddAssetForbidden {
	return &AddAssetForbidden{}
}

/*
AddAssetForbidden describes a response with status code 403, with default header values.

User is not authorized for request
*/
type AddAssetForbidden struct {
	Payload *models.Errors
}

// IsSuccess returns true when this add asset forbidden response has a 2xx status code
func (o *AddAssetForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this add asset forbidden response has a 3xx status code
func (o *AddAssetForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this add asset forbidden response has a 4xx status code
func (o *AddAssetForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this add asset forbidden response has a 5xx status code
func (o *AddAssetForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this add asset forbidden response a status code equal to that given
func (o *AddAssetForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the add asset forbidden response
func (o *AddAssetForbidden) Code() int {
	return 403
}

func (o *AddAssetForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /assets][%d] addAssetForbidden %s", 403, payload)
}

func (o *AddAssetForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /assets][%d] addAssetForbidden %s", 403, payload)
}

func (o *AddAssetForbidden) GetPayload() *models.Errors {
	return o.Payload
}

func (o *AddAssetForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAddAssetInternalServerError creates a AddAssetInternalServerError with default headers values
func NewAddAssetInternalServerError() *AddAssetInternalServerError {
	return &AddAssetInternalServerError{}
}

/*
AddAssetInternalServerError describes a response with status code 500, with default header values.

Server error, for more information see errorcode and message
*/
type AddAssetInternalServerError struct {
	Payload *models.Errors
}

// IsSuccess returns true when this add asset internal server error response has a 2xx status code
func (o *AddAssetInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this add asset internal server error response has a 3xx status code
func (o *AddAssetInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this add asset internal server error response has a 4xx status code
func (o *AddAssetInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this add asset internal server error response has a 5xx status code
func (o *AddAssetInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this add asset internal server error response a status code equal to that given
func (o *AddAssetInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the add asset internal server error response
func (o *AddAssetInternalServerError) Code() int {
	return 500
}

func (o *AddAssetInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /assets][%d] addAssetInternalServerError %s", 500, payload)
}

func (o *AddAssetInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /assets][%d] addAssetInternalServerError %s", 500, payload)
}

func (o *AddAssetInternalServerError) GetPayload() *models.Errors {
	return o.Payload
}

func (o *AddAssetInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAddAssetServiceUnavailable creates a AddAssetServiceUnavailable with default headers values
func NewAddAssetServiceUnavailable() *AddAssetServiceUnavailable {
	return &AddAssetServiceUnavailable{}
}

/*
AddAssetServiceUnavailable describes a response with status code 503, with default header values.

Service unavailable, for more information see errorcode and message
*/
type AddAssetServiceUnavailable struct {
	Payload *models.Errors
}

// IsSuccess returns true when this add asset service unavailable response has a 2xx status code
func (o *AddAssetServiceUnavailable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this add asset service unavailable response has a 3xx status code
func (o *AddAssetServiceUnavailable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this add asset service unavailable response has a 4xx status code
func (o *AddAssetServiceUnavailable) IsClientError() bool {
	return false
}

// IsServerError returns true when this add asset service unavailable response has a 5xx status code
func (o *AddAssetServiceUnavailable) IsServerError() bool {
	return true
}

// IsCode returns true when this add asset service unavailable response a status code equal to that given
func (o *AddAssetServiceUnavailable) IsCode(code int) bool {
	return code == 503
}

// Code gets the status code for the add asset service unavailable response
func (o *AddAssetServiceUnavailable) Code() int {
	return 503
}

func (o *AddAssetServiceUnavailable) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /assets][%d] addAssetServiceUnavailable %s", 503, payload)
}

func (o *AddAssetServiceUnavailable) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /assets][%d] addAssetServiceUnavailable %s", 503, payload)
}

func (o *AddAssetServiceUnavailable) GetPayload() *models.Errors {
	return o.Payload
}

func (o *AddAssetServiceUnavailable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
