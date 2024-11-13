// Code generated by go-swagger; DO NOT EDIT.

package files

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

// GetFileReader is a Reader for the GetFile structure.
type GetFileReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetFileReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetFileOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 304:
		result := NewGetFileNotModified()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetFileUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetFileForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetFileNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetFileInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /files/{fileId}] getFile", response, response.Code())
	}
}

// NewGetFileOK creates a GetFileOK with default headers values
func NewGetFileOK() *GetFileOK {
	return &GetFileOK{}
}

/*
GetFileOK describes a response with status code 200, with default header values.

Returns the file's metadata
*/
type GetFileOK struct {
	Payload *models.FileMetadataResource
}

// IsSuccess returns true when this get file o k response has a 2xx status code
func (o *GetFileOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get file o k response has a 3xx status code
func (o *GetFileOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file o k response has a 4xx status code
func (o *GetFileOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get file o k response has a 5xx status code
func (o *GetFileOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get file o k response a status code equal to that given
func (o *GetFileOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get file o k response
func (o *GetFileOK) Code() int {
	return 200
}

func (o *GetFileOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /files/{fileId}][%d] getFileOK %s", 200, payload)
}

func (o *GetFileOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /files/{fileId}][%d] getFileOK %s", 200, payload)
}

func (o *GetFileOK) GetPayload() *models.FileMetadataResource {
	return o.Payload
}

func (o *GetFileOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.FileMetadataResource)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFileNotModified creates a GetFileNotModified with default headers values
func NewGetFileNotModified() *GetFileNotModified {
	return &GetFileNotModified{}
}

/*
GetFileNotModified describes a response with status code 304, with default header values.

Resource have not been modified
*/
type GetFileNotModified struct {
}

// IsSuccess returns true when this get file not modified response has a 2xx status code
func (o *GetFileNotModified) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file not modified response has a 3xx status code
func (o *GetFileNotModified) IsRedirect() bool {
	return true
}

// IsClientError returns true when this get file not modified response has a 4xx status code
func (o *GetFileNotModified) IsClientError() bool {
	return false
}

// IsServerError returns true when this get file not modified response has a 5xx status code
func (o *GetFileNotModified) IsServerError() bool {
	return false
}

// IsCode returns true when this get file not modified response a status code equal to that given
func (o *GetFileNotModified) IsCode(code int) bool {
	return code == 304
}

// Code gets the status code for the get file not modified response
func (o *GetFileNotModified) Code() int {
	return 304
}

func (o *GetFileNotModified) Error() string {
	return fmt.Sprintf("[GET /files/{fileId}][%d] getFileNotModified", 304)
}

func (o *GetFileNotModified) String() string {
	return fmt.Sprintf("[GET /files/{fileId}][%d] getFileNotModified", 304)
}

func (o *GetFileNotModified) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetFileUnauthorized creates a GetFileUnauthorized with default headers values
func NewGetFileUnauthorized() *GetFileUnauthorized {
	return &GetFileUnauthorized{}
}

/*
GetFileUnauthorized describes a response with status code 401, with default header values.

User is not authenticated
*/
type GetFileUnauthorized struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get file unauthorized response has a 2xx status code
func (o *GetFileUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file unauthorized response has a 3xx status code
func (o *GetFileUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file unauthorized response has a 4xx status code
func (o *GetFileUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file unauthorized response has a 5xx status code
func (o *GetFileUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get file unauthorized response a status code equal to that given
func (o *GetFileUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get file unauthorized response
func (o *GetFileUnauthorized) Code() int {
	return 401
}

func (o *GetFileUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /files/{fileId}][%d] getFileUnauthorized %s", 401, payload)
}

func (o *GetFileUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /files/{fileId}][%d] getFileUnauthorized %s", 401, payload)
}

func (o *GetFileUnauthorized) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetFileUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFileForbidden creates a GetFileForbidden with default headers values
func NewGetFileForbidden() *GetFileForbidden {
	return &GetFileForbidden{}
}

/*
GetFileForbidden describes a response with status code 403, with default header values.

User is not authorized for request
*/
type GetFileForbidden struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get file forbidden response has a 2xx status code
func (o *GetFileForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file forbidden response has a 3xx status code
func (o *GetFileForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file forbidden response has a 4xx status code
func (o *GetFileForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file forbidden response has a 5xx status code
func (o *GetFileForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get file forbidden response a status code equal to that given
func (o *GetFileForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get file forbidden response
func (o *GetFileForbidden) Code() int {
	return 403
}

func (o *GetFileForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /files/{fileId}][%d] getFileForbidden %s", 403, payload)
}

func (o *GetFileForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /files/{fileId}][%d] getFileForbidden %s", 403, payload)
}

func (o *GetFileForbidden) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetFileForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFileNotFound creates a GetFileNotFound with default headers values
func NewGetFileNotFound() *GetFileNotFound {
	return &GetFileNotFound{}
}

/*
GetFileNotFound describes a response with status code 404, with default header values.

File not found
*/
type GetFileNotFound struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get file not found response has a 2xx status code
func (o *GetFileNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file not found response has a 3xx status code
func (o *GetFileNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file not found response has a 4xx status code
func (o *GetFileNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file not found response has a 5xx status code
func (o *GetFileNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get file not found response a status code equal to that given
func (o *GetFileNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get file not found response
func (o *GetFileNotFound) Code() int {
	return 404
}

func (o *GetFileNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /files/{fileId}][%d] getFileNotFound %s", 404, payload)
}

func (o *GetFileNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /files/{fileId}][%d] getFileNotFound %s", 404, payload)
}

func (o *GetFileNotFound) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetFileNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFileInternalServerError creates a GetFileInternalServerError with default headers values
func NewGetFileInternalServerError() *GetFileInternalServerError {
	return &GetFileInternalServerError{}
}

/*
GetFileInternalServerError describes a response with status code 500, with default header values.

Server error, for more information see errorcode and message
*/
type GetFileInternalServerError struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get file internal server error response has a 2xx status code
func (o *GetFileInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file internal server error response has a 3xx status code
func (o *GetFileInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file internal server error response has a 4xx status code
func (o *GetFileInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get file internal server error response has a 5xx status code
func (o *GetFileInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get file internal server error response a status code equal to that given
func (o *GetFileInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get file internal server error response
func (o *GetFileInternalServerError) Code() int {
	return 500
}

func (o *GetFileInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /files/{fileId}][%d] getFileInternalServerError %s", 500, payload)
}

func (o *GetFileInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /files/{fileId}][%d] getFileInternalServerError %s", 500, payload)
}

func (o *GetFileInternalServerError) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetFileInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
