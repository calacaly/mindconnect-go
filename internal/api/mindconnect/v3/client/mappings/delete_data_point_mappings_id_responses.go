// Code generated by go-swagger; DO NOT EDIT.

package mappings

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

// DeleteDataPointMappingsIDReader is a Reader for the DeleteDataPointMappingsID structure.
type DeleteDataPointMappingsIDReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteDataPointMappingsIDReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDeleteDataPointMappingsIDNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeleteDataPointMappingsIDBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDeleteDataPointMappingsIDUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteDataPointMappingsIDForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteDataPointMappingsIDNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		result := NewDeleteDataPointMappingsIDDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewDeleteDataPointMappingsIDNoContent creates a DeleteDataPointMappingsIDNoContent with default headers values
func NewDeleteDataPointMappingsIDNoContent() *DeleteDataPointMappingsIDNoContent {
	return &DeleteDataPointMappingsIDNoContent{}
}

/*
DeleteDataPointMappingsIDNoContent describes a response with status code 204, with default header values.

Deleted
*/
type DeleteDataPointMappingsIDNoContent struct {
}

// IsSuccess returns true when this delete data point mappings Id no content response has a 2xx status code
func (o *DeleteDataPointMappingsIDNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete data point mappings Id no content response has a 3xx status code
func (o *DeleteDataPointMappingsIDNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data point mappings Id no content response has a 4xx status code
func (o *DeleteDataPointMappingsIDNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete data point mappings Id no content response has a 5xx status code
func (o *DeleteDataPointMappingsIDNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data point mappings Id no content response a status code equal to that given
func (o *DeleteDataPointMappingsIDNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the delete data point mappings Id no content response
func (o *DeleteDataPointMappingsIDNoContent) Code() int {
	return 204
}

func (o *DeleteDataPointMappingsIDNoContent) Error() string {
	return fmt.Sprintf("[DELETE /dataPointMappings/{id}][%d] deleteDataPointMappingsIdNoContent", 204)
}

func (o *DeleteDataPointMappingsIDNoContent) String() string {
	return fmt.Sprintf("[DELETE /dataPointMappings/{id}][%d] deleteDataPointMappingsIdNoContent", 204)
}

func (o *DeleteDataPointMappingsIDNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteDataPointMappingsIDBadRequest creates a DeleteDataPointMappingsIDBadRequest with default headers values
func NewDeleteDataPointMappingsIDBadRequest() *DeleteDataPointMappingsIDBadRequest {
	return &DeleteDataPointMappingsIDBadRequest{}
}

/*
DeleteDataPointMappingsIDBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type DeleteDataPointMappingsIDBadRequest struct {
	Payload *models.Badrequest
}

// IsSuccess returns true when this delete data point mappings Id bad request response has a 2xx status code
func (o *DeleteDataPointMappingsIDBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data point mappings Id bad request response has a 3xx status code
func (o *DeleteDataPointMappingsIDBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data point mappings Id bad request response has a 4xx status code
func (o *DeleteDataPointMappingsIDBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete data point mappings Id bad request response has a 5xx status code
func (o *DeleteDataPointMappingsIDBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data point mappings Id bad request response a status code equal to that given
func (o *DeleteDataPointMappingsIDBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the delete data point mappings Id bad request response
func (o *DeleteDataPointMappingsIDBadRequest) Code() int {
	return 400
}

func (o *DeleteDataPointMappingsIDBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /dataPointMappings/{id}][%d] deleteDataPointMappingsIdBadRequest %s", 400, payload)
}

func (o *DeleteDataPointMappingsIDBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /dataPointMappings/{id}][%d] deleteDataPointMappingsIdBadRequest %s", 400, payload)
}

func (o *DeleteDataPointMappingsIDBadRequest) GetPayload() *models.Badrequest {
	return o.Payload
}

func (o *DeleteDataPointMappingsIDBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Badrequest)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataPointMappingsIDUnauthorized creates a DeleteDataPointMappingsIDUnauthorized with default headers values
func NewDeleteDataPointMappingsIDUnauthorized() *DeleteDataPointMappingsIDUnauthorized {
	return &DeleteDataPointMappingsIDUnauthorized{}
}

/*
DeleteDataPointMappingsIDUnauthorized describes a response with status code 401, with default header values.

unauthorized
*/
type DeleteDataPointMappingsIDUnauthorized struct {
	Payload *models.Unauthorized
}

// IsSuccess returns true when this delete data point mappings Id unauthorized response has a 2xx status code
func (o *DeleteDataPointMappingsIDUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data point mappings Id unauthorized response has a 3xx status code
func (o *DeleteDataPointMappingsIDUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data point mappings Id unauthorized response has a 4xx status code
func (o *DeleteDataPointMappingsIDUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete data point mappings Id unauthorized response has a 5xx status code
func (o *DeleteDataPointMappingsIDUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data point mappings Id unauthorized response a status code equal to that given
func (o *DeleteDataPointMappingsIDUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the delete data point mappings Id unauthorized response
func (o *DeleteDataPointMappingsIDUnauthorized) Code() int {
	return 401
}

func (o *DeleteDataPointMappingsIDUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /dataPointMappings/{id}][%d] deleteDataPointMappingsIdUnauthorized %s", 401, payload)
}

func (o *DeleteDataPointMappingsIDUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /dataPointMappings/{id}][%d] deleteDataPointMappingsIdUnauthorized %s", 401, payload)
}

func (o *DeleteDataPointMappingsIDUnauthorized) GetPayload() *models.Unauthorized {
	return o.Payload
}

func (o *DeleteDataPointMappingsIDUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Unauthorized)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataPointMappingsIDForbidden creates a DeleteDataPointMappingsIDForbidden with default headers values
func NewDeleteDataPointMappingsIDForbidden() *DeleteDataPointMappingsIDForbidden {
	return &DeleteDataPointMappingsIDForbidden{}
}

/*
DeleteDataPointMappingsIDForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeleteDataPointMappingsIDForbidden struct {
	Payload *models.Forbidden
}

// IsSuccess returns true when this delete data point mappings Id forbidden response has a 2xx status code
func (o *DeleteDataPointMappingsIDForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data point mappings Id forbidden response has a 3xx status code
func (o *DeleteDataPointMappingsIDForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data point mappings Id forbidden response has a 4xx status code
func (o *DeleteDataPointMappingsIDForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete data point mappings Id forbidden response has a 5xx status code
func (o *DeleteDataPointMappingsIDForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data point mappings Id forbidden response a status code equal to that given
func (o *DeleteDataPointMappingsIDForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the delete data point mappings Id forbidden response
func (o *DeleteDataPointMappingsIDForbidden) Code() int {
	return 403
}

func (o *DeleteDataPointMappingsIDForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /dataPointMappings/{id}][%d] deleteDataPointMappingsIdForbidden %s", 403, payload)
}

func (o *DeleteDataPointMappingsIDForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /dataPointMappings/{id}][%d] deleteDataPointMappingsIdForbidden %s", 403, payload)
}

func (o *DeleteDataPointMappingsIDForbidden) GetPayload() *models.Forbidden {
	return o.Payload
}

func (o *DeleteDataPointMappingsIDForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Forbidden)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataPointMappingsIDNotFound creates a DeleteDataPointMappingsIDNotFound with default headers values
func NewDeleteDataPointMappingsIDNotFound() *DeleteDataPointMappingsIDNotFound {
	return &DeleteDataPointMappingsIDNotFound{}
}

/*
DeleteDataPointMappingsIDNotFound describes a response with status code 404, with default header values.

Mapping not found
*/
type DeleteDataPointMappingsIDNotFound struct {
	Payload *models.Notfound
}

// IsSuccess returns true when this delete data point mappings Id not found response has a 2xx status code
func (o *DeleteDataPointMappingsIDNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data point mappings Id not found response has a 3xx status code
func (o *DeleteDataPointMappingsIDNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data point mappings Id not found response has a 4xx status code
func (o *DeleteDataPointMappingsIDNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete data point mappings Id not found response has a 5xx status code
func (o *DeleteDataPointMappingsIDNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data point mappings Id not found response a status code equal to that given
func (o *DeleteDataPointMappingsIDNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the delete data point mappings Id not found response
func (o *DeleteDataPointMappingsIDNotFound) Code() int {
	return 404
}

func (o *DeleteDataPointMappingsIDNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /dataPointMappings/{id}][%d] deleteDataPointMappingsIdNotFound %s", 404, payload)
}

func (o *DeleteDataPointMappingsIDNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /dataPointMappings/{id}][%d] deleteDataPointMappingsIdNotFound %s", 404, payload)
}

func (o *DeleteDataPointMappingsIDNotFound) GetPayload() *models.Notfound {
	return o.Payload
}

func (o *DeleteDataPointMappingsIDNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Notfound)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataPointMappingsIDDefault creates a DeleteDataPointMappingsIDDefault with default headers values
func NewDeleteDataPointMappingsIDDefault(code int) *DeleteDataPointMappingsIDDefault {
	return &DeleteDataPointMappingsIDDefault{
		_statusCode: code,
	}
}

/*
DeleteDataPointMappingsIDDefault describes a response with status code -1, with default header values.

unexpected error
*/
type DeleteDataPointMappingsIDDefault struct {
	_statusCode int

	Payload *models.Error
}

// IsSuccess returns true when this delete data point mappings ID default response has a 2xx status code
func (o *DeleteDataPointMappingsIDDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this delete data point mappings ID default response has a 3xx status code
func (o *DeleteDataPointMappingsIDDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this delete data point mappings ID default response has a 4xx status code
func (o *DeleteDataPointMappingsIDDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this delete data point mappings ID default response has a 5xx status code
func (o *DeleteDataPointMappingsIDDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this delete data point mappings ID default response a status code equal to that given
func (o *DeleteDataPointMappingsIDDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the delete data point mappings ID default response
func (o *DeleteDataPointMappingsIDDefault) Code() int {
	return o._statusCode
}

func (o *DeleteDataPointMappingsIDDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /dataPointMappings/{id}][%d] DeleteDataPointMappingsID default %s", o._statusCode, payload)
}

func (o *DeleteDataPointMappingsIDDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /dataPointMappings/{id}][%d] DeleteDataPointMappingsID default %s", o._statusCode, payload)
}

func (o *DeleteDataPointMappingsIDDefault) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteDataPointMappingsIDDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
