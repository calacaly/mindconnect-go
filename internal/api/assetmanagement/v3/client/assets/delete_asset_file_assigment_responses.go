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

// DeleteAssetFileAssigmentReader is a Reader for the DeleteAssetFileAssigment structure.
type DeleteAssetFileAssigmentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteAssetFileAssigmentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeleteAssetFileAssigmentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDeleteAssetFileAssigmentUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteAssetFileAssigmentForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteAssetFileAssigmentNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewDeleteAssetFileAssigmentPreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewDeleteAssetFileAssigmentInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 503:
		result := NewDeleteAssetFileAssigmentServiceUnavailable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /assets/{id}/fileAssignments/{key}] deleteAssetFileAssigment", response, response.Code())
	}
}

// NewDeleteAssetFileAssigmentOK creates a DeleteAssetFileAssigmentOK with default headers values
func NewDeleteAssetFileAssigmentOK() *DeleteAssetFileAssigmentOK {
	return &DeleteAssetFileAssigmentOK{}
}

/*
DeleteAssetFileAssigmentOK describes a response with status code 200, with default header values.

The assignment has been deleted
*/
type DeleteAssetFileAssigmentOK struct {
	Payload *models.AssetResourceWithHierarchyPath
}

// IsSuccess returns true when this delete asset file assigment o k response has a 2xx status code
func (o *DeleteAssetFileAssigmentOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete asset file assigment o k response has a 3xx status code
func (o *DeleteAssetFileAssigmentOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete asset file assigment o k response has a 4xx status code
func (o *DeleteAssetFileAssigmentOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete asset file assigment o k response has a 5xx status code
func (o *DeleteAssetFileAssigmentOK) IsServerError() bool {
	return false
}

// IsCode returns true when this delete asset file assigment o k response a status code equal to that given
func (o *DeleteAssetFileAssigmentOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the delete asset file assigment o k response
func (o *DeleteAssetFileAssigmentOK) Code() int {
	return 200
}

func (o *DeleteAssetFileAssigmentOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assets/{id}/fileAssignments/{key}][%d] deleteAssetFileAssigmentOK %s", 200, payload)
}

func (o *DeleteAssetFileAssigmentOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assets/{id}/fileAssignments/{key}][%d] deleteAssetFileAssigmentOK %s", 200, payload)
}

func (o *DeleteAssetFileAssigmentOK) GetPayload() *models.AssetResourceWithHierarchyPath {
	return o.Payload
}

func (o *DeleteAssetFileAssigmentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AssetResourceWithHierarchyPath)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteAssetFileAssigmentUnauthorized creates a DeleteAssetFileAssigmentUnauthorized with default headers values
func NewDeleteAssetFileAssigmentUnauthorized() *DeleteAssetFileAssigmentUnauthorized {
	return &DeleteAssetFileAssigmentUnauthorized{}
}

/*
DeleteAssetFileAssigmentUnauthorized describes a response with status code 401, with default header values.

User is not authenticated
*/
type DeleteAssetFileAssigmentUnauthorized struct {
	Payload *models.Errors
}

// IsSuccess returns true when this delete asset file assigment unauthorized response has a 2xx status code
func (o *DeleteAssetFileAssigmentUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete asset file assigment unauthorized response has a 3xx status code
func (o *DeleteAssetFileAssigmentUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete asset file assigment unauthorized response has a 4xx status code
func (o *DeleteAssetFileAssigmentUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete asset file assigment unauthorized response has a 5xx status code
func (o *DeleteAssetFileAssigmentUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this delete asset file assigment unauthorized response a status code equal to that given
func (o *DeleteAssetFileAssigmentUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the delete asset file assigment unauthorized response
func (o *DeleteAssetFileAssigmentUnauthorized) Code() int {
	return 401
}

func (o *DeleteAssetFileAssigmentUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assets/{id}/fileAssignments/{key}][%d] deleteAssetFileAssigmentUnauthorized %s", 401, payload)
}

func (o *DeleteAssetFileAssigmentUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assets/{id}/fileAssignments/{key}][%d] deleteAssetFileAssigmentUnauthorized %s", 401, payload)
}

func (o *DeleteAssetFileAssigmentUnauthorized) GetPayload() *models.Errors {
	return o.Payload
}

func (o *DeleteAssetFileAssigmentUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteAssetFileAssigmentForbidden creates a DeleteAssetFileAssigmentForbidden with default headers values
func NewDeleteAssetFileAssigmentForbidden() *DeleteAssetFileAssigmentForbidden {
	return &DeleteAssetFileAssigmentForbidden{}
}

/*
DeleteAssetFileAssigmentForbidden describes a response with status code 403, with default header values.

User is not authorized for request
*/
type DeleteAssetFileAssigmentForbidden struct {
	Payload *models.Errors
}

// IsSuccess returns true when this delete asset file assigment forbidden response has a 2xx status code
func (o *DeleteAssetFileAssigmentForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete asset file assigment forbidden response has a 3xx status code
func (o *DeleteAssetFileAssigmentForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete asset file assigment forbidden response has a 4xx status code
func (o *DeleteAssetFileAssigmentForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete asset file assigment forbidden response has a 5xx status code
func (o *DeleteAssetFileAssigmentForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete asset file assigment forbidden response a status code equal to that given
func (o *DeleteAssetFileAssigmentForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the delete asset file assigment forbidden response
func (o *DeleteAssetFileAssigmentForbidden) Code() int {
	return 403
}

func (o *DeleteAssetFileAssigmentForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assets/{id}/fileAssignments/{key}][%d] deleteAssetFileAssigmentForbidden %s", 403, payload)
}

func (o *DeleteAssetFileAssigmentForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assets/{id}/fileAssignments/{key}][%d] deleteAssetFileAssigmentForbidden %s", 403, payload)
}

func (o *DeleteAssetFileAssigmentForbidden) GetPayload() *models.Errors {
	return o.Payload
}

func (o *DeleteAssetFileAssigmentForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteAssetFileAssigmentNotFound creates a DeleteAssetFileAssigmentNotFound with default headers values
func NewDeleteAssetFileAssigmentNotFound() *DeleteAssetFileAssigmentNotFound {
	return &DeleteAssetFileAssigmentNotFound{}
}

/*
DeleteAssetFileAssigmentNotFound describes a response with status code 404, with default header values.

Asset or key not found
*/
type DeleteAssetFileAssigmentNotFound struct {
	Payload *models.Errors
}

// IsSuccess returns true when this delete asset file assigment not found response has a 2xx status code
func (o *DeleteAssetFileAssigmentNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete asset file assigment not found response has a 3xx status code
func (o *DeleteAssetFileAssigmentNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete asset file assigment not found response has a 4xx status code
func (o *DeleteAssetFileAssigmentNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete asset file assigment not found response has a 5xx status code
func (o *DeleteAssetFileAssigmentNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this delete asset file assigment not found response a status code equal to that given
func (o *DeleteAssetFileAssigmentNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the delete asset file assigment not found response
func (o *DeleteAssetFileAssigmentNotFound) Code() int {
	return 404
}

func (o *DeleteAssetFileAssigmentNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assets/{id}/fileAssignments/{key}][%d] deleteAssetFileAssigmentNotFound %s", 404, payload)
}

func (o *DeleteAssetFileAssigmentNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assets/{id}/fileAssignments/{key}][%d] deleteAssetFileAssigmentNotFound %s", 404, payload)
}

func (o *DeleteAssetFileAssigmentNotFound) GetPayload() *models.Errors {
	return o.Payload
}

func (o *DeleteAssetFileAssigmentNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteAssetFileAssigmentPreconditionFailed creates a DeleteAssetFileAssigmentPreconditionFailed with default headers values
func NewDeleteAssetFileAssigmentPreconditionFailed() *DeleteAssetFileAssigmentPreconditionFailed {
	return &DeleteAssetFileAssigmentPreconditionFailed{}
}

/*
DeleteAssetFileAssigmentPreconditionFailed describes a response with status code 412, with default header values.

Asset or the file assignment has changed in the background
*/
type DeleteAssetFileAssigmentPreconditionFailed struct {
	Payload *models.Errors
}

// IsSuccess returns true when this delete asset file assigment precondition failed response has a 2xx status code
func (o *DeleteAssetFileAssigmentPreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete asset file assigment precondition failed response has a 3xx status code
func (o *DeleteAssetFileAssigmentPreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete asset file assigment precondition failed response has a 4xx status code
func (o *DeleteAssetFileAssigmentPreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete asset file assigment precondition failed response has a 5xx status code
func (o *DeleteAssetFileAssigmentPreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this delete asset file assigment precondition failed response a status code equal to that given
func (o *DeleteAssetFileAssigmentPreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the delete asset file assigment precondition failed response
func (o *DeleteAssetFileAssigmentPreconditionFailed) Code() int {
	return 412
}

func (o *DeleteAssetFileAssigmentPreconditionFailed) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assets/{id}/fileAssignments/{key}][%d] deleteAssetFileAssigmentPreconditionFailed %s", 412, payload)
}

func (o *DeleteAssetFileAssigmentPreconditionFailed) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assets/{id}/fileAssignments/{key}][%d] deleteAssetFileAssigmentPreconditionFailed %s", 412, payload)
}

func (o *DeleteAssetFileAssigmentPreconditionFailed) GetPayload() *models.Errors {
	return o.Payload
}

func (o *DeleteAssetFileAssigmentPreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteAssetFileAssigmentInternalServerError creates a DeleteAssetFileAssigmentInternalServerError with default headers values
func NewDeleteAssetFileAssigmentInternalServerError() *DeleteAssetFileAssigmentInternalServerError {
	return &DeleteAssetFileAssigmentInternalServerError{}
}

/*
DeleteAssetFileAssigmentInternalServerError describes a response with status code 500, with default header values.

Server error, for more information see errorcode and message
*/
type DeleteAssetFileAssigmentInternalServerError struct {
	Payload *models.Errors
}

// IsSuccess returns true when this delete asset file assigment internal server error response has a 2xx status code
func (o *DeleteAssetFileAssigmentInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete asset file assigment internal server error response has a 3xx status code
func (o *DeleteAssetFileAssigmentInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete asset file assigment internal server error response has a 4xx status code
func (o *DeleteAssetFileAssigmentInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete asset file assigment internal server error response has a 5xx status code
func (o *DeleteAssetFileAssigmentInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this delete asset file assigment internal server error response a status code equal to that given
func (o *DeleteAssetFileAssigmentInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the delete asset file assigment internal server error response
func (o *DeleteAssetFileAssigmentInternalServerError) Code() int {
	return 500
}

func (o *DeleteAssetFileAssigmentInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assets/{id}/fileAssignments/{key}][%d] deleteAssetFileAssigmentInternalServerError %s", 500, payload)
}

func (o *DeleteAssetFileAssigmentInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assets/{id}/fileAssignments/{key}][%d] deleteAssetFileAssigmentInternalServerError %s", 500, payload)
}

func (o *DeleteAssetFileAssigmentInternalServerError) GetPayload() *models.Errors {
	return o.Payload
}

func (o *DeleteAssetFileAssigmentInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteAssetFileAssigmentServiceUnavailable creates a DeleteAssetFileAssigmentServiceUnavailable with default headers values
func NewDeleteAssetFileAssigmentServiceUnavailable() *DeleteAssetFileAssigmentServiceUnavailable {
	return &DeleteAssetFileAssigmentServiceUnavailable{}
}

/*
DeleteAssetFileAssigmentServiceUnavailable describes a response with status code 503, with default header values.

Service unavailable, for more information see errorcode and message
*/
type DeleteAssetFileAssigmentServiceUnavailable struct {
	Payload *models.Errors
}

// IsSuccess returns true when this delete asset file assigment service unavailable response has a 2xx status code
func (o *DeleteAssetFileAssigmentServiceUnavailable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete asset file assigment service unavailable response has a 3xx status code
func (o *DeleteAssetFileAssigmentServiceUnavailable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete asset file assigment service unavailable response has a 4xx status code
func (o *DeleteAssetFileAssigmentServiceUnavailable) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete asset file assigment service unavailable response has a 5xx status code
func (o *DeleteAssetFileAssigmentServiceUnavailable) IsServerError() bool {
	return true
}

// IsCode returns true when this delete asset file assigment service unavailable response a status code equal to that given
func (o *DeleteAssetFileAssigmentServiceUnavailable) IsCode(code int) bool {
	return code == 503
}

// Code gets the status code for the delete asset file assigment service unavailable response
func (o *DeleteAssetFileAssigmentServiceUnavailable) Code() int {
	return 503
}

func (o *DeleteAssetFileAssigmentServiceUnavailable) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assets/{id}/fileAssignments/{key}][%d] deleteAssetFileAssigmentServiceUnavailable %s", 503, payload)
}

func (o *DeleteAssetFileAssigmentServiceUnavailable) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assets/{id}/fileAssignments/{key}][%d] deleteAssetFileAssigmentServiceUnavailable %s", 503, payload)
}

func (o *DeleteAssetFileAssigmentServiceUnavailable) GetPayload() *models.Errors {
	return o.Payload
}

func (o *DeleteAssetFileAssigmentServiceUnavailable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
