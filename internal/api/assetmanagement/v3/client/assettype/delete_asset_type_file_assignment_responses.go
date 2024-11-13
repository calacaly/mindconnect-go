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

// DeleteAssetTypeFileAssignmentReader is a Reader for the DeleteAssetTypeFileAssignment structure.
type DeleteAssetTypeFileAssignmentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteAssetTypeFileAssignmentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeleteAssetTypeFileAssignmentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDeleteAssetTypeFileAssignmentUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteAssetTypeFileAssignmentForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteAssetTypeFileAssignmentNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewDeleteAssetTypeFileAssignmentPreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewDeleteAssetTypeFileAssignmentInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /assettypes/{id}/fileAssignments/{key}] deleteAssetTypeFileAssignment", response, response.Code())
	}
}

// NewDeleteAssetTypeFileAssignmentOK creates a DeleteAssetTypeFileAssignmentOK with default headers values
func NewDeleteAssetTypeFileAssignmentOK() *DeleteAssetTypeFileAssignmentOK {
	return &DeleteAssetTypeFileAssignmentOK{}
}

/*
DeleteAssetTypeFileAssignmentOK describes a response with status code 200, with default header values.

The assignment has been deleted
*/
type DeleteAssetTypeFileAssignmentOK struct {
	Payload *models.AssetTypeResource
}

// IsSuccess returns true when this delete asset type file assignment o k response has a 2xx status code
func (o *DeleteAssetTypeFileAssignmentOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete asset type file assignment o k response has a 3xx status code
func (o *DeleteAssetTypeFileAssignmentOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete asset type file assignment o k response has a 4xx status code
func (o *DeleteAssetTypeFileAssignmentOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete asset type file assignment o k response has a 5xx status code
func (o *DeleteAssetTypeFileAssignmentOK) IsServerError() bool {
	return false
}

// IsCode returns true when this delete asset type file assignment o k response a status code equal to that given
func (o *DeleteAssetTypeFileAssignmentOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the delete asset type file assignment o k response
func (o *DeleteAssetTypeFileAssignmentOK) Code() int {
	return 200
}

func (o *DeleteAssetTypeFileAssignmentOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assettypes/{id}/fileAssignments/{key}][%d] deleteAssetTypeFileAssignmentOK %s", 200, payload)
}

func (o *DeleteAssetTypeFileAssignmentOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assettypes/{id}/fileAssignments/{key}][%d] deleteAssetTypeFileAssignmentOK %s", 200, payload)
}

func (o *DeleteAssetTypeFileAssignmentOK) GetPayload() *models.AssetTypeResource {
	return o.Payload
}

func (o *DeleteAssetTypeFileAssignmentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AssetTypeResource)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteAssetTypeFileAssignmentUnauthorized creates a DeleteAssetTypeFileAssignmentUnauthorized with default headers values
func NewDeleteAssetTypeFileAssignmentUnauthorized() *DeleteAssetTypeFileAssignmentUnauthorized {
	return &DeleteAssetTypeFileAssignmentUnauthorized{}
}

/*
DeleteAssetTypeFileAssignmentUnauthorized describes a response with status code 401, with default header values.

User is not authenticated
*/
type DeleteAssetTypeFileAssignmentUnauthorized struct {
	Payload *models.Errors
}

// IsSuccess returns true when this delete asset type file assignment unauthorized response has a 2xx status code
func (o *DeleteAssetTypeFileAssignmentUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete asset type file assignment unauthorized response has a 3xx status code
func (o *DeleteAssetTypeFileAssignmentUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete asset type file assignment unauthorized response has a 4xx status code
func (o *DeleteAssetTypeFileAssignmentUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete asset type file assignment unauthorized response has a 5xx status code
func (o *DeleteAssetTypeFileAssignmentUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this delete asset type file assignment unauthorized response a status code equal to that given
func (o *DeleteAssetTypeFileAssignmentUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the delete asset type file assignment unauthorized response
func (o *DeleteAssetTypeFileAssignmentUnauthorized) Code() int {
	return 401
}

func (o *DeleteAssetTypeFileAssignmentUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assettypes/{id}/fileAssignments/{key}][%d] deleteAssetTypeFileAssignmentUnauthorized %s", 401, payload)
}

func (o *DeleteAssetTypeFileAssignmentUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assettypes/{id}/fileAssignments/{key}][%d] deleteAssetTypeFileAssignmentUnauthorized %s", 401, payload)
}

func (o *DeleteAssetTypeFileAssignmentUnauthorized) GetPayload() *models.Errors {
	return o.Payload
}

func (o *DeleteAssetTypeFileAssignmentUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteAssetTypeFileAssignmentForbidden creates a DeleteAssetTypeFileAssignmentForbidden with default headers values
func NewDeleteAssetTypeFileAssignmentForbidden() *DeleteAssetTypeFileAssignmentForbidden {
	return &DeleteAssetTypeFileAssignmentForbidden{}
}

/*
DeleteAssetTypeFileAssignmentForbidden describes a response with status code 403, with default header values.

User is not authorized for request
*/
type DeleteAssetTypeFileAssignmentForbidden struct {
	Payload *models.Errors
}

// IsSuccess returns true when this delete asset type file assignment forbidden response has a 2xx status code
func (o *DeleteAssetTypeFileAssignmentForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete asset type file assignment forbidden response has a 3xx status code
func (o *DeleteAssetTypeFileAssignmentForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete asset type file assignment forbidden response has a 4xx status code
func (o *DeleteAssetTypeFileAssignmentForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete asset type file assignment forbidden response has a 5xx status code
func (o *DeleteAssetTypeFileAssignmentForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete asset type file assignment forbidden response a status code equal to that given
func (o *DeleteAssetTypeFileAssignmentForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the delete asset type file assignment forbidden response
func (o *DeleteAssetTypeFileAssignmentForbidden) Code() int {
	return 403
}

func (o *DeleteAssetTypeFileAssignmentForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assettypes/{id}/fileAssignments/{key}][%d] deleteAssetTypeFileAssignmentForbidden %s", 403, payload)
}

func (o *DeleteAssetTypeFileAssignmentForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assettypes/{id}/fileAssignments/{key}][%d] deleteAssetTypeFileAssignmentForbidden %s", 403, payload)
}

func (o *DeleteAssetTypeFileAssignmentForbidden) GetPayload() *models.Errors {
	return o.Payload
}

func (o *DeleteAssetTypeFileAssignmentForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteAssetTypeFileAssignmentNotFound creates a DeleteAssetTypeFileAssignmentNotFound with default headers values
func NewDeleteAssetTypeFileAssignmentNotFound() *DeleteAssetTypeFileAssignmentNotFound {
	return &DeleteAssetTypeFileAssignmentNotFound{}
}

/*
DeleteAssetTypeFileAssignmentNotFound describes a response with status code 404, with default header values.

Asset type or key not found
*/
type DeleteAssetTypeFileAssignmentNotFound struct {
	Payload *models.Errors
}

// IsSuccess returns true when this delete asset type file assignment not found response has a 2xx status code
func (o *DeleteAssetTypeFileAssignmentNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete asset type file assignment not found response has a 3xx status code
func (o *DeleteAssetTypeFileAssignmentNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete asset type file assignment not found response has a 4xx status code
func (o *DeleteAssetTypeFileAssignmentNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete asset type file assignment not found response has a 5xx status code
func (o *DeleteAssetTypeFileAssignmentNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this delete asset type file assignment not found response a status code equal to that given
func (o *DeleteAssetTypeFileAssignmentNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the delete asset type file assignment not found response
func (o *DeleteAssetTypeFileAssignmentNotFound) Code() int {
	return 404
}

func (o *DeleteAssetTypeFileAssignmentNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assettypes/{id}/fileAssignments/{key}][%d] deleteAssetTypeFileAssignmentNotFound %s", 404, payload)
}

func (o *DeleteAssetTypeFileAssignmentNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assettypes/{id}/fileAssignments/{key}][%d] deleteAssetTypeFileAssignmentNotFound %s", 404, payload)
}

func (o *DeleteAssetTypeFileAssignmentNotFound) GetPayload() *models.Errors {
	return o.Payload
}

func (o *DeleteAssetTypeFileAssignmentNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteAssetTypeFileAssignmentPreconditionFailed creates a DeleteAssetTypeFileAssignmentPreconditionFailed with default headers values
func NewDeleteAssetTypeFileAssignmentPreconditionFailed() *DeleteAssetTypeFileAssignmentPreconditionFailed {
	return &DeleteAssetTypeFileAssignmentPreconditionFailed{}
}

/*
DeleteAssetTypeFileAssignmentPreconditionFailed describes a response with status code 412, with default header values.

Asset type or the file assignment has changed in the background
*/
type DeleteAssetTypeFileAssignmentPreconditionFailed struct {
	Payload *models.Errors
}

// IsSuccess returns true when this delete asset type file assignment precondition failed response has a 2xx status code
func (o *DeleteAssetTypeFileAssignmentPreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete asset type file assignment precondition failed response has a 3xx status code
func (o *DeleteAssetTypeFileAssignmentPreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete asset type file assignment precondition failed response has a 4xx status code
func (o *DeleteAssetTypeFileAssignmentPreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete asset type file assignment precondition failed response has a 5xx status code
func (o *DeleteAssetTypeFileAssignmentPreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this delete asset type file assignment precondition failed response a status code equal to that given
func (o *DeleteAssetTypeFileAssignmentPreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the delete asset type file assignment precondition failed response
func (o *DeleteAssetTypeFileAssignmentPreconditionFailed) Code() int {
	return 412
}

func (o *DeleteAssetTypeFileAssignmentPreconditionFailed) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assettypes/{id}/fileAssignments/{key}][%d] deleteAssetTypeFileAssignmentPreconditionFailed %s", 412, payload)
}

func (o *DeleteAssetTypeFileAssignmentPreconditionFailed) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assettypes/{id}/fileAssignments/{key}][%d] deleteAssetTypeFileAssignmentPreconditionFailed %s", 412, payload)
}

func (o *DeleteAssetTypeFileAssignmentPreconditionFailed) GetPayload() *models.Errors {
	return o.Payload
}

func (o *DeleteAssetTypeFileAssignmentPreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteAssetTypeFileAssignmentInternalServerError creates a DeleteAssetTypeFileAssignmentInternalServerError with default headers values
func NewDeleteAssetTypeFileAssignmentInternalServerError() *DeleteAssetTypeFileAssignmentInternalServerError {
	return &DeleteAssetTypeFileAssignmentInternalServerError{}
}

/*
DeleteAssetTypeFileAssignmentInternalServerError describes a response with status code 500, with default header values.

Server error, for more information see errorcode and message
*/
type DeleteAssetTypeFileAssignmentInternalServerError struct {
	Payload *models.Errors
}

// IsSuccess returns true when this delete asset type file assignment internal server error response has a 2xx status code
func (o *DeleteAssetTypeFileAssignmentInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete asset type file assignment internal server error response has a 3xx status code
func (o *DeleteAssetTypeFileAssignmentInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete asset type file assignment internal server error response has a 4xx status code
func (o *DeleteAssetTypeFileAssignmentInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete asset type file assignment internal server error response has a 5xx status code
func (o *DeleteAssetTypeFileAssignmentInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this delete asset type file assignment internal server error response a status code equal to that given
func (o *DeleteAssetTypeFileAssignmentInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the delete asset type file assignment internal server error response
func (o *DeleteAssetTypeFileAssignmentInternalServerError) Code() int {
	return 500
}

func (o *DeleteAssetTypeFileAssignmentInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assettypes/{id}/fileAssignments/{key}][%d] deleteAssetTypeFileAssignmentInternalServerError %s", 500, payload)
}

func (o *DeleteAssetTypeFileAssignmentInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /assettypes/{id}/fileAssignments/{key}][%d] deleteAssetTypeFileAssignmentInternalServerError %s", 500, payload)
}

func (o *DeleteAssetTypeFileAssignmentInternalServerError) GetPayload() *models.Errors {
	return o.Payload
}

func (o *DeleteAssetTypeFileAssignmentInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}