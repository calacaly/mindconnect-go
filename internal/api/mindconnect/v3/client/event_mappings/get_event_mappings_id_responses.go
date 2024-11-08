// Code generated by go-swagger; DO NOT EDIT.

package event_mappings

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

// GetEventMappingsIDReader is a Reader for the GetEventMappingsID structure.
type GetEventMappingsIDReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetEventMappingsIDReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetEventMappingsIDOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetEventMappingsIDBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetEventMappingsIDUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetEventMappingsIDForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetEventMappingsIDNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		result := NewGetEventMappingsIDDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewGetEventMappingsIDOK creates a GetEventMappingsIDOK with default headers values
func NewGetEventMappingsIDOK() *GetEventMappingsIDOK {
	return &GetEventMappingsIDOK{}
}

/*
GetEventMappingsIDOK describes a response with status code 200, with default header values.

OK
*/
type GetEventMappingsIDOK struct {
	Payload *models.EventMapping
}

// IsSuccess returns true when this get event mappings Id o k response has a 2xx status code
func (o *GetEventMappingsIDOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get event mappings Id o k response has a 3xx status code
func (o *GetEventMappingsIDOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get event mappings Id o k response has a 4xx status code
func (o *GetEventMappingsIDOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get event mappings Id o k response has a 5xx status code
func (o *GetEventMappingsIDOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get event mappings Id o k response a status code equal to that given
func (o *GetEventMappingsIDOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get event mappings Id o k response
func (o *GetEventMappingsIDOK) Code() int {
	return 200
}

func (o *GetEventMappingsIDOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /eventMappings/{id}][%d] getEventMappingsIdOK %s", 200, payload)
}

func (o *GetEventMappingsIDOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /eventMappings/{id}][%d] getEventMappingsIdOK %s", 200, payload)
}

func (o *GetEventMappingsIDOK) GetPayload() *models.EventMapping {
	return o.Payload
}

func (o *GetEventMappingsIDOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.EventMapping)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetEventMappingsIDBadRequest creates a GetEventMappingsIDBadRequest with default headers values
func NewGetEventMappingsIDBadRequest() *GetEventMappingsIDBadRequest {
	return &GetEventMappingsIDBadRequest{}
}

/*
GetEventMappingsIDBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetEventMappingsIDBadRequest struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get event mappings Id bad request response has a 2xx status code
func (o *GetEventMappingsIDBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get event mappings Id bad request response has a 3xx status code
func (o *GetEventMappingsIDBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get event mappings Id bad request response has a 4xx status code
func (o *GetEventMappingsIDBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get event mappings Id bad request response has a 5xx status code
func (o *GetEventMappingsIDBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get event mappings Id bad request response a status code equal to that given
func (o *GetEventMappingsIDBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get event mappings Id bad request response
func (o *GetEventMappingsIDBadRequest) Code() int {
	return 400
}

func (o *GetEventMappingsIDBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /eventMappings/{id}][%d] getEventMappingsIdBadRequest %s", 400, payload)
}

func (o *GetEventMappingsIDBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /eventMappings/{id}][%d] getEventMappingsIdBadRequest %s", 400, payload)
}

func (o *GetEventMappingsIDBadRequest) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetEventMappingsIDBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetEventMappingsIDUnauthorized creates a GetEventMappingsIDUnauthorized with default headers values
func NewGetEventMappingsIDUnauthorized() *GetEventMappingsIDUnauthorized {
	return &GetEventMappingsIDUnauthorized{}
}

/*
GetEventMappingsIDUnauthorized describes a response with status code 401, with default header values.

unauthorized
*/
type GetEventMappingsIDUnauthorized struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get event mappings Id unauthorized response has a 2xx status code
func (o *GetEventMappingsIDUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get event mappings Id unauthorized response has a 3xx status code
func (o *GetEventMappingsIDUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get event mappings Id unauthorized response has a 4xx status code
func (o *GetEventMappingsIDUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get event mappings Id unauthorized response has a 5xx status code
func (o *GetEventMappingsIDUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get event mappings Id unauthorized response a status code equal to that given
func (o *GetEventMappingsIDUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get event mappings Id unauthorized response
func (o *GetEventMappingsIDUnauthorized) Code() int {
	return 401
}

func (o *GetEventMappingsIDUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /eventMappings/{id}][%d] getEventMappingsIdUnauthorized %s", 401, payload)
}

func (o *GetEventMappingsIDUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /eventMappings/{id}][%d] getEventMappingsIdUnauthorized %s", 401, payload)
}

func (o *GetEventMappingsIDUnauthorized) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetEventMappingsIDUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetEventMappingsIDForbidden creates a GetEventMappingsIDForbidden with default headers values
func NewGetEventMappingsIDForbidden() *GetEventMappingsIDForbidden {
	return &GetEventMappingsIDForbidden{}
}

/*
GetEventMappingsIDForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetEventMappingsIDForbidden struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get event mappings Id forbidden response has a 2xx status code
func (o *GetEventMappingsIDForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get event mappings Id forbidden response has a 3xx status code
func (o *GetEventMappingsIDForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get event mappings Id forbidden response has a 4xx status code
func (o *GetEventMappingsIDForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get event mappings Id forbidden response has a 5xx status code
func (o *GetEventMappingsIDForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get event mappings Id forbidden response a status code equal to that given
func (o *GetEventMappingsIDForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get event mappings Id forbidden response
func (o *GetEventMappingsIDForbidden) Code() int {
	return 403
}

func (o *GetEventMappingsIDForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /eventMappings/{id}][%d] getEventMappingsIdForbidden %s", 403, payload)
}

func (o *GetEventMappingsIDForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /eventMappings/{id}][%d] getEventMappingsIdForbidden %s", 403, payload)
}

func (o *GetEventMappingsIDForbidden) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetEventMappingsIDForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetEventMappingsIDNotFound creates a GetEventMappingsIDNotFound with default headers values
func NewGetEventMappingsIDNotFound() *GetEventMappingsIDNotFound {
	return &GetEventMappingsIDNotFound{}
}

/*
GetEventMappingsIDNotFound describes a response with status code 404, with default header values.

Mapping not found
*/
type GetEventMappingsIDNotFound struct {
	Payload *models.Errors
}

// IsSuccess returns true when this get event mappings Id not found response has a 2xx status code
func (o *GetEventMappingsIDNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get event mappings Id not found response has a 3xx status code
func (o *GetEventMappingsIDNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get event mappings Id not found response has a 4xx status code
func (o *GetEventMappingsIDNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get event mappings Id not found response has a 5xx status code
func (o *GetEventMappingsIDNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get event mappings Id not found response a status code equal to that given
func (o *GetEventMappingsIDNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get event mappings Id not found response
func (o *GetEventMappingsIDNotFound) Code() int {
	return 404
}

func (o *GetEventMappingsIDNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /eventMappings/{id}][%d] getEventMappingsIdNotFound %s", 404, payload)
}

func (o *GetEventMappingsIDNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /eventMappings/{id}][%d] getEventMappingsIdNotFound %s", 404, payload)
}

func (o *GetEventMappingsIDNotFound) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetEventMappingsIDNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetEventMappingsIDDefault creates a GetEventMappingsIDDefault with default headers values
func NewGetEventMappingsIDDefault(code int) *GetEventMappingsIDDefault {
	return &GetEventMappingsIDDefault{
		_statusCode: code,
	}
}

/*
GetEventMappingsIDDefault describes a response with status code -1, with default header values.

unexpected error
*/
type GetEventMappingsIDDefault struct {
	_statusCode int

	Payload *models.Errors
}

// IsSuccess returns true when this get event mappings ID default response has a 2xx status code
func (o *GetEventMappingsIDDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this get event mappings ID default response has a 3xx status code
func (o *GetEventMappingsIDDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this get event mappings ID default response has a 4xx status code
func (o *GetEventMappingsIDDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this get event mappings ID default response has a 5xx status code
func (o *GetEventMappingsIDDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this get event mappings ID default response a status code equal to that given
func (o *GetEventMappingsIDDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the get event mappings ID default response
func (o *GetEventMappingsIDDefault) Code() int {
	return o._statusCode
}

func (o *GetEventMappingsIDDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /eventMappings/{id}][%d] GetEventMappingsID default %s", o._statusCode, payload)
}

func (o *GetEventMappingsIDDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /eventMappings/{id}][%d] GetEventMappingsID default %s", o._statusCode, payload)
}

func (o *GetEventMappingsIDDefault) GetPayload() *models.Errors {
	return o.Payload
}

func (o *GetEventMappingsIDDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Errors)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}