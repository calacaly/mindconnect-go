// Code generated by go-swagger; DO NOT EDIT.

package diagnostic_activations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/calacaly/mindconnect-go/internal/api/mindconnect/v3/models"
)

// DeleteDiagnosticActivationsIDReader is a Reader for the DeleteDiagnosticActivationsID structure.
type DeleteDiagnosticActivationsIDReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteDiagnosticActivationsIDReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDeleteDiagnosticActivationsIDNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeleteDiagnosticActivationsIDBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDeleteDiagnosticActivationsIDUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteDiagnosticActivationsIDForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteDiagnosticActivationsIDNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		result := NewDeleteDiagnosticActivationsIDDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewDeleteDiagnosticActivationsIDNoContent creates a DeleteDiagnosticActivationsIDNoContent with default headers values
func NewDeleteDiagnosticActivationsIDNoContent() *DeleteDiagnosticActivationsIDNoContent {
	return &DeleteDiagnosticActivationsIDNoContent{}
}

/*
DeleteDiagnosticActivationsIDNoContent describes a response with status code 204, with default header values.

No Content
*/
type DeleteDiagnosticActivationsIDNoContent struct {
}

// IsSuccess returns true when this delete diagnostic activations Id no content response has a 2xx status code
func (o *DeleteDiagnosticActivationsIDNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete diagnostic activations Id no content response has a 3xx status code
func (o *DeleteDiagnosticActivationsIDNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete diagnostic activations Id no content response has a 4xx status code
func (o *DeleteDiagnosticActivationsIDNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete diagnostic activations Id no content response has a 5xx status code
func (o *DeleteDiagnosticActivationsIDNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this delete diagnostic activations Id no content response a status code equal to that given
func (o *DeleteDiagnosticActivationsIDNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the delete diagnostic activations Id no content response
func (o *DeleteDiagnosticActivationsIDNoContent) Code() int {
	return 204
}

func (o *DeleteDiagnosticActivationsIDNoContent) Error() string {
	return fmt.Sprintf("[DELETE /diagnosticActivations/{id}][%d] deleteDiagnosticActivationsIdNoContent", 204)
}

func (o *DeleteDiagnosticActivationsIDNoContent) String() string {
	return fmt.Sprintf("[DELETE /diagnosticActivations/{id}][%d] deleteDiagnosticActivationsIdNoContent", 204)
}

func (o *DeleteDiagnosticActivationsIDNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteDiagnosticActivationsIDBadRequest creates a DeleteDiagnosticActivationsIDBadRequest with default headers values
func NewDeleteDiagnosticActivationsIDBadRequest() *DeleteDiagnosticActivationsIDBadRequest {
	return &DeleteDiagnosticActivationsIDBadRequest{}
}

/*
DeleteDiagnosticActivationsIDBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type DeleteDiagnosticActivationsIDBadRequest struct {
	Payload *models.Badrequest
}

// IsSuccess returns true when this delete diagnostic activations Id bad request response has a 2xx status code
func (o *DeleteDiagnosticActivationsIDBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete diagnostic activations Id bad request response has a 3xx status code
func (o *DeleteDiagnosticActivationsIDBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete diagnostic activations Id bad request response has a 4xx status code
func (o *DeleteDiagnosticActivationsIDBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete diagnostic activations Id bad request response has a 5xx status code
func (o *DeleteDiagnosticActivationsIDBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this delete diagnostic activations Id bad request response a status code equal to that given
func (o *DeleteDiagnosticActivationsIDBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the delete diagnostic activations Id bad request response
func (o *DeleteDiagnosticActivationsIDBadRequest) Code() int {
	return 400
}

func (o *DeleteDiagnosticActivationsIDBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /diagnosticActivations/{id}][%d] deleteDiagnosticActivationsIdBadRequest %s", 400, payload)
}

func (o *DeleteDiagnosticActivationsIDBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /diagnosticActivations/{id}][%d] deleteDiagnosticActivationsIdBadRequest %s", 400, payload)
}

func (o *DeleteDiagnosticActivationsIDBadRequest) GetPayload() *models.Badrequest {
	return o.Payload
}

func (o *DeleteDiagnosticActivationsIDBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Badrequest)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDiagnosticActivationsIDUnauthorized creates a DeleteDiagnosticActivationsIDUnauthorized with default headers values
func NewDeleteDiagnosticActivationsIDUnauthorized() *DeleteDiagnosticActivationsIDUnauthorized {
	return &DeleteDiagnosticActivationsIDUnauthorized{}
}

/*
DeleteDiagnosticActivationsIDUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type DeleteDiagnosticActivationsIDUnauthorized struct {
	Payload *models.Unauthorized
}

// IsSuccess returns true when this delete diagnostic activations Id unauthorized response has a 2xx status code
func (o *DeleteDiagnosticActivationsIDUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete diagnostic activations Id unauthorized response has a 3xx status code
func (o *DeleteDiagnosticActivationsIDUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete diagnostic activations Id unauthorized response has a 4xx status code
func (o *DeleteDiagnosticActivationsIDUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete diagnostic activations Id unauthorized response has a 5xx status code
func (o *DeleteDiagnosticActivationsIDUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this delete diagnostic activations Id unauthorized response a status code equal to that given
func (o *DeleteDiagnosticActivationsIDUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the delete diagnostic activations Id unauthorized response
func (o *DeleteDiagnosticActivationsIDUnauthorized) Code() int {
	return 401
}

func (o *DeleteDiagnosticActivationsIDUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /diagnosticActivations/{id}][%d] deleteDiagnosticActivationsIdUnauthorized %s", 401, payload)
}

func (o *DeleteDiagnosticActivationsIDUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /diagnosticActivations/{id}][%d] deleteDiagnosticActivationsIdUnauthorized %s", 401, payload)
}

func (o *DeleteDiagnosticActivationsIDUnauthorized) GetPayload() *models.Unauthorized {
	return o.Payload
}

func (o *DeleteDiagnosticActivationsIDUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Unauthorized)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDiagnosticActivationsIDForbidden creates a DeleteDiagnosticActivationsIDForbidden with default headers values
func NewDeleteDiagnosticActivationsIDForbidden() *DeleteDiagnosticActivationsIDForbidden {
	return &DeleteDiagnosticActivationsIDForbidden{}
}

/*
DeleteDiagnosticActivationsIDForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeleteDiagnosticActivationsIDForbidden struct {
	Payload *models.Forbidden
}

// IsSuccess returns true when this delete diagnostic activations Id forbidden response has a 2xx status code
func (o *DeleteDiagnosticActivationsIDForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete diagnostic activations Id forbidden response has a 3xx status code
func (o *DeleteDiagnosticActivationsIDForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete diagnostic activations Id forbidden response has a 4xx status code
func (o *DeleteDiagnosticActivationsIDForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete diagnostic activations Id forbidden response has a 5xx status code
func (o *DeleteDiagnosticActivationsIDForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete diagnostic activations Id forbidden response a status code equal to that given
func (o *DeleteDiagnosticActivationsIDForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the delete diagnostic activations Id forbidden response
func (o *DeleteDiagnosticActivationsIDForbidden) Code() int {
	return 403
}

func (o *DeleteDiagnosticActivationsIDForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /diagnosticActivations/{id}][%d] deleteDiagnosticActivationsIdForbidden %s", 403, payload)
}

func (o *DeleteDiagnosticActivationsIDForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /diagnosticActivations/{id}][%d] deleteDiagnosticActivationsIdForbidden %s", 403, payload)
}

func (o *DeleteDiagnosticActivationsIDForbidden) GetPayload() *models.Forbidden {
	return o.Payload
}

func (o *DeleteDiagnosticActivationsIDForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Forbidden)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDiagnosticActivationsIDNotFound creates a DeleteDiagnosticActivationsIDNotFound with default headers values
func NewDeleteDiagnosticActivationsIDNotFound() *DeleteDiagnosticActivationsIDNotFound {
	return &DeleteDiagnosticActivationsIDNotFound{}
}

/*
DeleteDiagnosticActivationsIDNotFound describes a response with status code 404, with default header values.

Not Found
*/
type DeleteDiagnosticActivationsIDNotFound struct {
	Payload *models.Notfound
}

// IsSuccess returns true when this delete diagnostic activations Id not found response has a 2xx status code
func (o *DeleteDiagnosticActivationsIDNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete diagnostic activations Id not found response has a 3xx status code
func (o *DeleteDiagnosticActivationsIDNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete diagnostic activations Id not found response has a 4xx status code
func (o *DeleteDiagnosticActivationsIDNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete diagnostic activations Id not found response has a 5xx status code
func (o *DeleteDiagnosticActivationsIDNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this delete diagnostic activations Id not found response a status code equal to that given
func (o *DeleteDiagnosticActivationsIDNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the delete diagnostic activations Id not found response
func (o *DeleteDiagnosticActivationsIDNotFound) Code() int {
	return 404
}

func (o *DeleteDiagnosticActivationsIDNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /diagnosticActivations/{id}][%d] deleteDiagnosticActivationsIdNotFound %s", 404, payload)
}

func (o *DeleteDiagnosticActivationsIDNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /diagnosticActivations/{id}][%d] deleteDiagnosticActivationsIdNotFound %s", 404, payload)
}

func (o *DeleteDiagnosticActivationsIDNotFound) GetPayload() *models.Notfound {
	return o.Payload
}

func (o *DeleteDiagnosticActivationsIDNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Notfound)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDiagnosticActivationsIDDefault creates a DeleteDiagnosticActivationsIDDefault with default headers values
func NewDeleteDiagnosticActivationsIDDefault(code int) *DeleteDiagnosticActivationsIDDefault {
	return &DeleteDiagnosticActivationsIDDefault{
		_statusCode: code,
	}
}

/*
DeleteDiagnosticActivationsIDDefault describes a response with status code -1, with default header values.

unexpected error
*/
type DeleteDiagnosticActivationsIDDefault struct {
	_statusCode int

	Payload *models.Error
}

// IsSuccess returns true when this delete diagnostic activations ID default response has a 2xx status code
func (o *DeleteDiagnosticActivationsIDDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this delete diagnostic activations ID default response has a 3xx status code
func (o *DeleteDiagnosticActivationsIDDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this delete diagnostic activations ID default response has a 4xx status code
func (o *DeleteDiagnosticActivationsIDDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this delete diagnostic activations ID default response has a 5xx status code
func (o *DeleteDiagnosticActivationsIDDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this delete diagnostic activations ID default response a status code equal to that given
func (o *DeleteDiagnosticActivationsIDDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the delete diagnostic activations ID default response
func (o *DeleteDiagnosticActivationsIDDefault) Code() int {
	return o._statusCode
}

func (o *DeleteDiagnosticActivationsIDDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /diagnosticActivations/{id}][%d] DeleteDiagnosticActivationsID default %s", o._statusCode, payload)
}

func (o *DeleteDiagnosticActivationsIDDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /diagnosticActivations/{id}][%d] DeleteDiagnosticActivationsID default %s", o._statusCode, payload)
}

func (o *DeleteDiagnosticActivationsIDDefault) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteDiagnosticActivationsIDDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
