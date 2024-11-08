// Code generated by go-swagger; DO NOT EDIT.

package record_recovery

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

// DeleteRecoverableRecordsIDReader is a Reader for the DeleteRecoverableRecordsID structure.
type DeleteRecoverableRecordsIDReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteRecoverableRecordsIDReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDeleteRecoverableRecordsIDNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeleteRecoverableRecordsIDBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDeleteRecoverableRecordsIDUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteRecoverableRecordsIDForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteRecoverableRecordsIDNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		result := NewDeleteRecoverableRecordsIDDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewDeleteRecoverableRecordsIDNoContent creates a DeleteRecoverableRecordsIDNoContent with default headers values
func NewDeleteRecoverableRecordsIDNoContent() *DeleteRecoverableRecordsIDNoContent {
	return &DeleteRecoverableRecordsIDNoContent{}
}

/*
DeleteRecoverableRecordsIDNoContent describes a response with status code 204, with default header values.

Deleted
*/
type DeleteRecoverableRecordsIDNoContent struct {
}

// IsSuccess returns true when this delete recoverable records Id no content response has a 2xx status code
func (o *DeleteRecoverableRecordsIDNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete recoverable records Id no content response has a 3xx status code
func (o *DeleteRecoverableRecordsIDNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete recoverable records Id no content response has a 4xx status code
func (o *DeleteRecoverableRecordsIDNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete recoverable records Id no content response has a 5xx status code
func (o *DeleteRecoverableRecordsIDNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this delete recoverable records Id no content response a status code equal to that given
func (o *DeleteRecoverableRecordsIDNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the delete recoverable records Id no content response
func (o *DeleteRecoverableRecordsIDNoContent) Code() int {
	return 204
}

func (o *DeleteRecoverableRecordsIDNoContent) Error() string {
	return fmt.Sprintf("[DELETE /recoverableRecords/{id}][%d] deleteRecoverableRecordsIdNoContent", 204)
}

func (o *DeleteRecoverableRecordsIDNoContent) String() string {
	return fmt.Sprintf("[DELETE /recoverableRecords/{id}][%d] deleteRecoverableRecordsIdNoContent", 204)
}

func (o *DeleteRecoverableRecordsIDNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteRecoverableRecordsIDBadRequest creates a DeleteRecoverableRecordsIDBadRequest with default headers values
func NewDeleteRecoverableRecordsIDBadRequest() *DeleteRecoverableRecordsIDBadRequest {
	return &DeleteRecoverableRecordsIDBadRequest{}
}

/*
DeleteRecoverableRecordsIDBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type DeleteRecoverableRecordsIDBadRequest struct {
	Payload *models.Badrequest
}

// IsSuccess returns true when this delete recoverable records Id bad request response has a 2xx status code
func (o *DeleteRecoverableRecordsIDBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete recoverable records Id bad request response has a 3xx status code
func (o *DeleteRecoverableRecordsIDBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete recoverable records Id bad request response has a 4xx status code
func (o *DeleteRecoverableRecordsIDBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete recoverable records Id bad request response has a 5xx status code
func (o *DeleteRecoverableRecordsIDBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this delete recoverable records Id bad request response a status code equal to that given
func (o *DeleteRecoverableRecordsIDBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the delete recoverable records Id bad request response
func (o *DeleteRecoverableRecordsIDBadRequest) Code() int {
	return 400
}

func (o *DeleteRecoverableRecordsIDBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /recoverableRecords/{id}][%d] deleteRecoverableRecordsIdBadRequest %s", 400, payload)
}

func (o *DeleteRecoverableRecordsIDBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /recoverableRecords/{id}][%d] deleteRecoverableRecordsIdBadRequest %s", 400, payload)
}

func (o *DeleteRecoverableRecordsIDBadRequest) GetPayload() *models.Badrequest {
	return o.Payload
}

func (o *DeleteRecoverableRecordsIDBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Badrequest)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteRecoverableRecordsIDUnauthorized creates a DeleteRecoverableRecordsIDUnauthorized with default headers values
func NewDeleteRecoverableRecordsIDUnauthorized() *DeleteRecoverableRecordsIDUnauthorized {
	return &DeleteRecoverableRecordsIDUnauthorized{}
}

/*
DeleteRecoverableRecordsIDUnauthorized describes a response with status code 401, with default header values.

unauthorized
*/
type DeleteRecoverableRecordsIDUnauthorized struct {
	Payload *models.Unauthorized
}

// IsSuccess returns true when this delete recoverable records Id unauthorized response has a 2xx status code
func (o *DeleteRecoverableRecordsIDUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete recoverable records Id unauthorized response has a 3xx status code
func (o *DeleteRecoverableRecordsIDUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete recoverable records Id unauthorized response has a 4xx status code
func (o *DeleteRecoverableRecordsIDUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete recoverable records Id unauthorized response has a 5xx status code
func (o *DeleteRecoverableRecordsIDUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this delete recoverable records Id unauthorized response a status code equal to that given
func (o *DeleteRecoverableRecordsIDUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the delete recoverable records Id unauthorized response
func (o *DeleteRecoverableRecordsIDUnauthorized) Code() int {
	return 401
}

func (o *DeleteRecoverableRecordsIDUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /recoverableRecords/{id}][%d] deleteRecoverableRecordsIdUnauthorized %s", 401, payload)
}

func (o *DeleteRecoverableRecordsIDUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /recoverableRecords/{id}][%d] deleteRecoverableRecordsIdUnauthorized %s", 401, payload)
}

func (o *DeleteRecoverableRecordsIDUnauthorized) GetPayload() *models.Unauthorized {
	return o.Payload
}

func (o *DeleteRecoverableRecordsIDUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Unauthorized)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteRecoverableRecordsIDForbidden creates a DeleteRecoverableRecordsIDForbidden with default headers values
func NewDeleteRecoverableRecordsIDForbidden() *DeleteRecoverableRecordsIDForbidden {
	return &DeleteRecoverableRecordsIDForbidden{}
}

/*
DeleteRecoverableRecordsIDForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeleteRecoverableRecordsIDForbidden struct {
	Payload *models.Forbidden
}

// IsSuccess returns true when this delete recoverable records Id forbidden response has a 2xx status code
func (o *DeleteRecoverableRecordsIDForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete recoverable records Id forbidden response has a 3xx status code
func (o *DeleteRecoverableRecordsIDForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete recoverable records Id forbidden response has a 4xx status code
func (o *DeleteRecoverableRecordsIDForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete recoverable records Id forbidden response has a 5xx status code
func (o *DeleteRecoverableRecordsIDForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete recoverable records Id forbidden response a status code equal to that given
func (o *DeleteRecoverableRecordsIDForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the delete recoverable records Id forbidden response
func (o *DeleteRecoverableRecordsIDForbidden) Code() int {
	return 403
}

func (o *DeleteRecoverableRecordsIDForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /recoverableRecords/{id}][%d] deleteRecoverableRecordsIdForbidden %s", 403, payload)
}

func (o *DeleteRecoverableRecordsIDForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /recoverableRecords/{id}][%d] deleteRecoverableRecordsIdForbidden %s", 403, payload)
}

func (o *DeleteRecoverableRecordsIDForbidden) GetPayload() *models.Forbidden {
	return o.Payload
}

func (o *DeleteRecoverableRecordsIDForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Forbidden)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteRecoverableRecordsIDNotFound creates a DeleteRecoverableRecordsIDNotFound with default headers values
func NewDeleteRecoverableRecordsIDNotFound() *DeleteRecoverableRecordsIDNotFound {
	return &DeleteRecoverableRecordsIDNotFound{}
}

/*
DeleteRecoverableRecordsIDNotFound describes a response with status code 404, with default header values.

Recoverable record not found
*/
type DeleteRecoverableRecordsIDNotFound struct {
	Payload *models.Notfound
}

// IsSuccess returns true when this delete recoverable records Id not found response has a 2xx status code
func (o *DeleteRecoverableRecordsIDNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete recoverable records Id not found response has a 3xx status code
func (o *DeleteRecoverableRecordsIDNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete recoverable records Id not found response has a 4xx status code
func (o *DeleteRecoverableRecordsIDNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete recoverable records Id not found response has a 5xx status code
func (o *DeleteRecoverableRecordsIDNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this delete recoverable records Id not found response a status code equal to that given
func (o *DeleteRecoverableRecordsIDNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the delete recoverable records Id not found response
func (o *DeleteRecoverableRecordsIDNotFound) Code() int {
	return 404
}

func (o *DeleteRecoverableRecordsIDNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /recoverableRecords/{id}][%d] deleteRecoverableRecordsIdNotFound %s", 404, payload)
}

func (o *DeleteRecoverableRecordsIDNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /recoverableRecords/{id}][%d] deleteRecoverableRecordsIdNotFound %s", 404, payload)
}

func (o *DeleteRecoverableRecordsIDNotFound) GetPayload() *models.Notfound {
	return o.Payload
}

func (o *DeleteRecoverableRecordsIDNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Notfound)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteRecoverableRecordsIDDefault creates a DeleteRecoverableRecordsIDDefault with default headers values
func NewDeleteRecoverableRecordsIDDefault(code int) *DeleteRecoverableRecordsIDDefault {
	return &DeleteRecoverableRecordsIDDefault{
		_statusCode: code,
	}
}

/*
DeleteRecoverableRecordsIDDefault describes a response with status code -1, with default header values.

unexpected error
*/
type DeleteRecoverableRecordsIDDefault struct {
	_statusCode int

	Payload *models.Error
}

// IsSuccess returns true when this delete recoverable records ID default response has a 2xx status code
func (o *DeleteRecoverableRecordsIDDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this delete recoverable records ID default response has a 3xx status code
func (o *DeleteRecoverableRecordsIDDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this delete recoverable records ID default response has a 4xx status code
func (o *DeleteRecoverableRecordsIDDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this delete recoverable records ID default response has a 5xx status code
func (o *DeleteRecoverableRecordsIDDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this delete recoverable records ID default response a status code equal to that given
func (o *DeleteRecoverableRecordsIDDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the delete recoverable records ID default response
func (o *DeleteRecoverableRecordsIDDefault) Code() int {
	return o._statusCode
}

func (o *DeleteRecoverableRecordsIDDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /recoverableRecords/{id}][%d] DeleteRecoverableRecordsID default %s", o._statusCode, payload)
}

func (o *DeleteRecoverableRecordsIDDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /recoverableRecords/{id}][%d] DeleteRecoverableRecordsID default %s", o._statusCode, payload)
}

func (o *DeleteRecoverableRecordsIDDefault) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteRecoverableRecordsIDDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
