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

// GetAssetTypeReader is a Reader for the GetAssetType structure.
type GetAssetTypeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAssetTypeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAssetTypeOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 304:
		result := NewGetAssetTypeNotModified()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 400:
		result := NewGetAssetTypeBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetAssetTypeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetAssetTypeForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetAssetTypeInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /assettypes/{id}] getAssetType", response, response.Code())
	}
}

// NewGetAssetTypeOK creates a GetAssetTypeOK with default headers values
func NewGetAssetTypeOK() *GetAssetTypeOK {
	return &GetAssetTypeOK{}
}

/*
GetAssetTypeOK describes a response with status code 200, with default header values.

Returns the asset type
*/
type GetAssetTypeOK struct {
	Payload *models.AssetTypeResource
}

// IsSuccess returns true when this get asset type o k response has a 2xx status code
func (o *GetAssetTypeOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get asset type o k response has a 3xx status code
func (o *GetAssetTypeOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get asset type o k response has a 4xx status code
func (o *GetAssetTypeOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get asset type o k response has a 5xx status code
func (o *GetAssetTypeOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get asset type o k response a status code equal to that given
func (o *GetAssetTypeOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get asset type o k response
func (o *GetAssetTypeOK) Code() int {
	return 200
}

func (o *GetAssetTypeOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes/{id}][%d] getAssetTypeOK %s", 200, payload)
}

func (o *GetAssetTypeOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes/{id}][%d] getAssetTypeOK %s", 200, payload)
}

func (o *GetAssetTypeOK) GetPayload() *models.AssetTypeResource {
	return o.Payload
}

func (o *GetAssetTypeOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AssetTypeResource)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAssetTypeNotModified creates a GetAssetTypeNotModified with default headers values
func NewGetAssetTypeNotModified() *GetAssetTypeNotModified {
	return &GetAssetTypeNotModified{}
}

/*
GetAssetTypeNotModified describes a response with status code 304, with default header values.

AssetType not changed
*/
type GetAssetTypeNotModified struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get asset type not modified response has a 2xx status code
func (o *GetAssetTypeNotModified) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get asset type not modified response has a 3xx status code
func (o *GetAssetTypeNotModified) IsRedirect() bool {
	return true
}

// IsClientError returns true when this get asset type not modified response has a 4xx status code
func (o *GetAssetTypeNotModified) IsClientError() bool {
	return false
}

// IsServerError returns true when this get asset type not modified response has a 5xx status code
func (o *GetAssetTypeNotModified) IsServerError() bool {
	return false
}

// IsCode returns true when this get asset type not modified response a status code equal to that given
func (o *GetAssetTypeNotModified) IsCode(code int) bool {
	return code == 304
}

// Code gets the status code for the get asset type not modified response
func (o *GetAssetTypeNotModified) Code() int {
	return 304
}

func (o *GetAssetTypeNotModified) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes/{id}][%d] getAssetTypeNotModified %s", 304, payload)
}

func (o *GetAssetTypeNotModified) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes/{id}][%d] getAssetTypeNotModified %s", 304, payload)
}

func (o *GetAssetTypeNotModified) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetAssetTypeNotModified) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAssetTypeBadRequest creates a GetAssetTypeBadRequest with default headers values
func NewGetAssetTypeBadRequest() *GetAssetTypeBadRequest {
	return &GetAssetTypeBadRequest{}
}

/*
GetAssetTypeBadRequest describes a response with status code 400, with default header values.

Invalid request
*/
type GetAssetTypeBadRequest struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get asset type bad request response has a 2xx status code
func (o *GetAssetTypeBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get asset type bad request response has a 3xx status code
func (o *GetAssetTypeBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get asset type bad request response has a 4xx status code
func (o *GetAssetTypeBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get asset type bad request response has a 5xx status code
func (o *GetAssetTypeBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get asset type bad request response a status code equal to that given
func (o *GetAssetTypeBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get asset type bad request response
func (o *GetAssetTypeBadRequest) Code() int {
	return 400
}

func (o *GetAssetTypeBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes/{id}][%d] getAssetTypeBadRequest %s", 400, payload)
}

func (o *GetAssetTypeBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes/{id}][%d] getAssetTypeBadRequest %s", 400, payload)
}

func (o *GetAssetTypeBadRequest) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetAssetTypeBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAssetTypeUnauthorized creates a GetAssetTypeUnauthorized with default headers values
func NewGetAssetTypeUnauthorized() *GetAssetTypeUnauthorized {
	return &GetAssetTypeUnauthorized{}
}

/*
GetAssetTypeUnauthorized describes a response with status code 401, with default header values.

User is not authenticated
*/
type GetAssetTypeUnauthorized struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get asset type unauthorized response has a 2xx status code
func (o *GetAssetTypeUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get asset type unauthorized response has a 3xx status code
func (o *GetAssetTypeUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get asset type unauthorized response has a 4xx status code
func (o *GetAssetTypeUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get asset type unauthorized response has a 5xx status code
func (o *GetAssetTypeUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get asset type unauthorized response a status code equal to that given
func (o *GetAssetTypeUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get asset type unauthorized response
func (o *GetAssetTypeUnauthorized) Code() int {
	return 401
}

func (o *GetAssetTypeUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes/{id}][%d] getAssetTypeUnauthorized %s", 401, payload)
}

func (o *GetAssetTypeUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes/{id}][%d] getAssetTypeUnauthorized %s", 401, payload)
}

func (o *GetAssetTypeUnauthorized) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetAssetTypeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAssetTypeForbidden creates a GetAssetTypeForbidden with default headers values
func NewGetAssetTypeForbidden() *GetAssetTypeForbidden {
	return &GetAssetTypeForbidden{}
}

/*
GetAssetTypeForbidden describes a response with status code 403, with default header values.

User is not authorized for request
*/
type GetAssetTypeForbidden struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get asset type forbidden response has a 2xx status code
func (o *GetAssetTypeForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get asset type forbidden response has a 3xx status code
func (o *GetAssetTypeForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get asset type forbidden response has a 4xx status code
func (o *GetAssetTypeForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get asset type forbidden response has a 5xx status code
func (o *GetAssetTypeForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get asset type forbidden response a status code equal to that given
func (o *GetAssetTypeForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get asset type forbidden response
func (o *GetAssetTypeForbidden) Code() int {
	return 403
}

func (o *GetAssetTypeForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes/{id}][%d] getAssetTypeForbidden %s", 403, payload)
}

func (o *GetAssetTypeForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes/{id}][%d] getAssetTypeForbidden %s", 403, payload)
}

func (o *GetAssetTypeForbidden) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetAssetTypeForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAssetTypeInternalServerError creates a GetAssetTypeInternalServerError with default headers values
func NewGetAssetTypeInternalServerError() *GetAssetTypeInternalServerError {
	return &GetAssetTypeInternalServerError{}
}

/*
GetAssetTypeInternalServerError describes a response with status code 500, with default header values.

Server error, for more information see errorcode and message
*/
type GetAssetTypeInternalServerError struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get asset type internal server error response has a 2xx status code
func (o *GetAssetTypeInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get asset type internal server error response has a 3xx status code
func (o *GetAssetTypeInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get asset type internal server error response has a 4xx status code
func (o *GetAssetTypeInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get asset type internal server error response has a 5xx status code
func (o *GetAssetTypeInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get asset type internal server error response a status code equal to that given
func (o *GetAssetTypeInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get asset type internal server error response
func (o *GetAssetTypeInternalServerError) Code() int {
	return 500
}

func (o *GetAssetTypeInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes/{id}][%d] getAssetTypeInternalServerError %s", 500, payload)
}

func (o *GetAssetTypeInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assettypes/{id}][%d] getAssetTypeInternalServerError %s", 500, payload)
}

func (o *GetAssetTypeInternalServerError) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetAssetTypeInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}