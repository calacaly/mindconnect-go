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

// GetRootAssetReader is a Reader for the GetRootAsset structure.
type GetRootAssetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetRootAssetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetRootAssetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 304:
		result := NewGetRootAssetNotModified()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetRootAssetUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetRootAssetForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetRootAssetNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetRootAssetInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /assets/root] getRootAsset", response, response.Code())
	}
}

// NewGetRootAssetOK creates a GetRootAssetOK with default headers values
func NewGetRootAssetOK() *GetRootAssetOK {
	return &GetRootAssetOK{}
}

/*
GetRootAssetOK describes a response with status code 200, with default header values.

Returns the root asset of the user.
*/
type GetRootAssetOK struct {

	/* ETag hash of the resource
	 */
	ETag string

	Payload *models.RootAssetResource
}

// IsSuccess returns true when this get root asset o k response has a 2xx status code
func (o *GetRootAssetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get root asset o k response has a 3xx status code
func (o *GetRootAssetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get root asset o k response has a 4xx status code
func (o *GetRootAssetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get root asset o k response has a 5xx status code
func (o *GetRootAssetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get root asset o k response a status code equal to that given
func (o *GetRootAssetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get root asset o k response
func (o *GetRootAssetOK) Code() int {
	return 200
}

func (o *GetRootAssetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/root][%d] getRootAssetOK %s", 200, payload)
}

func (o *GetRootAssetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/root][%d] getRootAssetOK %s", 200, payload)
}

func (o *GetRootAssetOK) GetPayload() *models.RootAssetResource {
	return o.Payload
}

func (o *GetRootAssetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header ETag
	hdrETag := response.GetHeader("ETag")

	if hdrETag != "" {
		o.ETag = hdrETag
	}

	o.Payload = new(models.RootAssetResource)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetRootAssetNotModified creates a GetRootAssetNotModified with default headers values
func NewGetRootAssetNotModified() *GetRootAssetNotModified {
	return &GetRootAssetNotModified{}
}

/*
GetRootAssetNotModified describes a response with status code 304, with default header values.

Resource asset is not modified
*/
type GetRootAssetNotModified struct {
}

// IsSuccess returns true when this get root asset not modified response has a 2xx status code
func (o *GetRootAssetNotModified) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get root asset not modified response has a 3xx status code
func (o *GetRootAssetNotModified) IsRedirect() bool {
	return true
}

// IsClientError returns true when this get root asset not modified response has a 4xx status code
func (o *GetRootAssetNotModified) IsClientError() bool {
	return false
}

// IsServerError returns true when this get root asset not modified response has a 5xx status code
func (o *GetRootAssetNotModified) IsServerError() bool {
	return false
}

// IsCode returns true when this get root asset not modified response a status code equal to that given
func (o *GetRootAssetNotModified) IsCode(code int) bool {
	return code == 304
}

// Code gets the status code for the get root asset not modified response
func (o *GetRootAssetNotModified) Code() int {
	return 304
}

func (o *GetRootAssetNotModified) Error() string {
	return fmt.Sprintf("[GET /assets/root][%d] getRootAssetNotModified", 304)
}

func (o *GetRootAssetNotModified) String() string {
	return fmt.Sprintf("[GET /assets/root][%d] getRootAssetNotModified", 304)
}

func (o *GetRootAssetNotModified) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetRootAssetUnauthorized creates a GetRootAssetUnauthorized with default headers values
func NewGetRootAssetUnauthorized() *GetRootAssetUnauthorized {
	return &GetRootAssetUnauthorized{}
}

/*
GetRootAssetUnauthorized describes a response with status code 401, with default header values.

User is not authenticated
*/
type GetRootAssetUnauthorized struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get root asset unauthorized response has a 2xx status code
func (o *GetRootAssetUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get root asset unauthorized response has a 3xx status code
func (o *GetRootAssetUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get root asset unauthorized response has a 4xx status code
func (o *GetRootAssetUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get root asset unauthorized response has a 5xx status code
func (o *GetRootAssetUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get root asset unauthorized response a status code equal to that given
func (o *GetRootAssetUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get root asset unauthorized response
func (o *GetRootAssetUnauthorized) Code() int {
	return 401
}

func (o *GetRootAssetUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/root][%d] getRootAssetUnauthorized %s", 401, payload)
}

func (o *GetRootAssetUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/root][%d] getRootAssetUnauthorized %s", 401, payload)
}

func (o *GetRootAssetUnauthorized) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetRootAssetUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetRootAssetForbidden creates a GetRootAssetForbidden with default headers values
func NewGetRootAssetForbidden() *GetRootAssetForbidden {
	return &GetRootAssetForbidden{}
}

/*
GetRootAssetForbidden describes a response with status code 403, with default header values.

User is not authorized for request
*/
type GetRootAssetForbidden struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get root asset forbidden response has a 2xx status code
func (o *GetRootAssetForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get root asset forbidden response has a 3xx status code
func (o *GetRootAssetForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get root asset forbidden response has a 4xx status code
func (o *GetRootAssetForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get root asset forbidden response has a 5xx status code
func (o *GetRootAssetForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get root asset forbidden response a status code equal to that given
func (o *GetRootAssetForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get root asset forbidden response
func (o *GetRootAssetForbidden) Code() int {
	return 403
}

func (o *GetRootAssetForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/root][%d] getRootAssetForbidden %s", 403, payload)
}

func (o *GetRootAssetForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/root][%d] getRootAssetForbidden %s", 403, payload)
}

func (o *GetRootAssetForbidden) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetRootAssetForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetRootAssetNotFound creates a GetRootAssetNotFound with default headers values
func NewGetRootAssetNotFound() *GetRootAssetNotFound {
	return &GetRootAssetNotFound{}
}

/*
GetRootAssetNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetRootAssetNotFound struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get root asset not found response has a 2xx status code
func (o *GetRootAssetNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get root asset not found response has a 3xx status code
func (o *GetRootAssetNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get root asset not found response has a 4xx status code
func (o *GetRootAssetNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get root asset not found response has a 5xx status code
func (o *GetRootAssetNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get root asset not found response a status code equal to that given
func (o *GetRootAssetNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get root asset not found response
func (o *GetRootAssetNotFound) Code() int {
	return 404
}

func (o *GetRootAssetNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/root][%d] getRootAssetNotFound %s", 404, payload)
}

func (o *GetRootAssetNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/root][%d] getRootAssetNotFound %s", 404, payload)
}

func (o *GetRootAssetNotFound) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetRootAssetNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetRootAssetInternalServerError creates a GetRootAssetInternalServerError with default headers values
func NewGetRootAssetInternalServerError() *GetRootAssetInternalServerError {
	return &GetRootAssetInternalServerError{}
}

/*
GetRootAssetInternalServerError describes a response with status code 500, with default header values.

Server error, for more information see errorcode and message
*/
type GetRootAssetInternalServerError struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get root asset internal server error response has a 2xx status code
func (o *GetRootAssetInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get root asset internal server error response has a 3xx status code
func (o *GetRootAssetInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get root asset internal server error response has a 4xx status code
func (o *GetRootAssetInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get root asset internal server error response has a 5xx status code
func (o *GetRootAssetInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get root asset internal server error response a status code equal to that given
func (o *GetRootAssetInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get root asset internal server error response
func (o *GetRootAssetInternalServerError) Code() int {
	return 500
}

func (o *GetRootAssetInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/root][%d] getRootAssetInternalServerError %s", 500, payload)
}

func (o *GetRootAssetInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /assets/root][%d] getRootAssetInternalServerError %s", 500, payload)
}

func (o *GetRootAssetInternalServerError) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetRootAssetInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
