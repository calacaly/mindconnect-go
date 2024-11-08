// Code generated by go-swagger; DO NOT EDIT.

package registration_operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/calacaly/mindconnect-go/internal/api/agentmanagement/v3/models"
)

// PutRegisterClientIDReader is a Reader for the PutRegisterClientID structure.
type PutRegisterClientIDReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PutRegisterClientIDReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPutRegisterClientIDOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPutRegisterClientIDBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPutRegisterClientIDUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewPutRegisterClientIDTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPutRegisterClientIDInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		result := NewPutRegisterClientIDDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPutRegisterClientIDOK creates a PutRegisterClientIDOK with default headers values
func NewPutRegisterClientIDOK() *PutRegisterClientIDOK {
	return &PutRegisterClientIDOK{}
}

/*
PutRegisterClientIDOK describes a response with status code 200, with default header values.

OK
*/
type PutRegisterClientIDOK struct {
	Payload *models.ClientIdentifier
}

// IsSuccess returns true when this put register client Id o k response has a 2xx status code
func (o *PutRegisterClientIDOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this put register client Id o k response has a 3xx status code
func (o *PutRegisterClientIDOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this put register client Id o k response has a 4xx status code
func (o *PutRegisterClientIDOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this put register client Id o k response has a 5xx status code
func (o *PutRegisterClientIDOK) IsServerError() bool {
	return false
}

// IsCode returns true when this put register client Id o k response a status code equal to that given
func (o *PutRegisterClientIDOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the put register client Id o k response
func (o *PutRegisterClientIDOK) Code() int {
	return 200
}

func (o *PutRegisterClientIDOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /register/{client_id}][%d] putRegisterClientIdOK %s", 200, payload)
}

func (o *PutRegisterClientIDOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /register/{client_id}][%d] putRegisterClientIdOK %s", 200, payload)
}

func (o *PutRegisterClientIDOK) GetPayload() *models.ClientIdentifier {
	return o.Payload
}

func (o *PutRegisterClientIDOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ClientIdentifier)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPutRegisterClientIDBadRequest creates a PutRegisterClientIDBadRequest with default headers values
func NewPutRegisterClientIDBadRequest() *PutRegisterClientIDBadRequest {
	return &PutRegisterClientIDBadRequest{}
}

/*
PutRegisterClientIDBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type PutRegisterClientIDBadRequest struct {
	Payload *models.BadrequestIAM
}

// IsSuccess returns true when this put register client Id bad request response has a 2xx status code
func (o *PutRegisterClientIDBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this put register client Id bad request response has a 3xx status code
func (o *PutRegisterClientIDBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this put register client Id bad request response has a 4xx status code
func (o *PutRegisterClientIDBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this put register client Id bad request response has a 5xx status code
func (o *PutRegisterClientIDBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this put register client Id bad request response a status code equal to that given
func (o *PutRegisterClientIDBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the put register client Id bad request response
func (o *PutRegisterClientIDBadRequest) Code() int {
	return 400
}

func (o *PutRegisterClientIDBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /register/{client_id}][%d] putRegisterClientIdBadRequest %s", 400, payload)
}

func (o *PutRegisterClientIDBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /register/{client_id}][%d] putRegisterClientIdBadRequest %s", 400, payload)
}

func (o *PutRegisterClientIDBadRequest) GetPayload() *models.BadrequestIAM {
	return o.Payload
}

func (o *PutRegisterClientIDBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BadrequestIAM)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPutRegisterClientIDUnauthorized creates a PutRegisterClientIDUnauthorized with default headers values
func NewPutRegisterClientIDUnauthorized() *PutRegisterClientIDUnauthorized {
	return &PutRegisterClientIDUnauthorized{}
}

/*
PutRegisterClientIDUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type PutRegisterClientIDUnauthorized struct {
	Payload *models.UnauthorizedIAM
}

// IsSuccess returns true when this put register client Id unauthorized response has a 2xx status code
func (o *PutRegisterClientIDUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this put register client Id unauthorized response has a 3xx status code
func (o *PutRegisterClientIDUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this put register client Id unauthorized response has a 4xx status code
func (o *PutRegisterClientIDUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this put register client Id unauthorized response has a 5xx status code
func (o *PutRegisterClientIDUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this put register client Id unauthorized response a status code equal to that given
func (o *PutRegisterClientIDUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the put register client Id unauthorized response
func (o *PutRegisterClientIDUnauthorized) Code() int {
	return 401
}

func (o *PutRegisterClientIDUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /register/{client_id}][%d] putRegisterClientIdUnauthorized %s", 401, payload)
}

func (o *PutRegisterClientIDUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /register/{client_id}][%d] putRegisterClientIdUnauthorized %s", 401, payload)
}

func (o *PutRegisterClientIDUnauthorized) GetPayload() *models.UnauthorizedIAM {
	return o.Payload
}

func (o *PutRegisterClientIDUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.UnauthorizedIAM)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPutRegisterClientIDTooManyRequests creates a PutRegisterClientIDTooManyRequests with default headers values
func NewPutRegisterClientIDTooManyRequests() *PutRegisterClientIDTooManyRequests {
	return &PutRegisterClientIDTooManyRequests{}
}

/*
PutRegisterClientIDTooManyRequests describes a response with status code 429, with default header values.

API rate limit exceeded.
*/
type PutRegisterClientIDTooManyRequests struct {
	Payload *models.APIRateLimitExceeded
}

// IsSuccess returns true when this put register client Id too many requests response has a 2xx status code
func (o *PutRegisterClientIDTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this put register client Id too many requests response has a 3xx status code
func (o *PutRegisterClientIDTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this put register client Id too many requests response has a 4xx status code
func (o *PutRegisterClientIDTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this put register client Id too many requests response has a 5xx status code
func (o *PutRegisterClientIDTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this put register client Id too many requests response a status code equal to that given
func (o *PutRegisterClientIDTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the put register client Id too many requests response
func (o *PutRegisterClientIDTooManyRequests) Code() int {
	return 429
}

func (o *PutRegisterClientIDTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /register/{client_id}][%d] putRegisterClientIdTooManyRequests %s", 429, payload)
}

func (o *PutRegisterClientIDTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /register/{client_id}][%d] putRegisterClientIdTooManyRequests %s", 429, payload)
}

func (o *PutRegisterClientIDTooManyRequests) GetPayload() *models.APIRateLimitExceeded {
	return o.Payload
}

func (o *PutRegisterClientIDTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIRateLimitExceeded)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPutRegisterClientIDInternalServerError creates a PutRegisterClientIDInternalServerError with default headers values
func NewPutRegisterClientIDInternalServerError() *PutRegisterClientIDInternalServerError {
	return &PutRegisterClientIDInternalServerError{}
}

/*
PutRegisterClientIDInternalServerError describes a response with status code 500, with default header values.

unexpected error
*/
type PutRegisterClientIDInternalServerError struct {
	Payload *models.Error
}

// IsSuccess returns true when this put register client Id internal server error response has a 2xx status code
func (o *PutRegisterClientIDInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this put register client Id internal server error response has a 3xx status code
func (o *PutRegisterClientIDInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this put register client Id internal server error response has a 4xx status code
func (o *PutRegisterClientIDInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this put register client Id internal server error response has a 5xx status code
func (o *PutRegisterClientIDInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this put register client Id internal server error response a status code equal to that given
func (o *PutRegisterClientIDInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the put register client Id internal server error response
func (o *PutRegisterClientIDInternalServerError) Code() int {
	return 500
}

func (o *PutRegisterClientIDInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /register/{client_id}][%d] putRegisterClientIdInternalServerError %s", 500, payload)
}

func (o *PutRegisterClientIDInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /register/{client_id}][%d] putRegisterClientIdInternalServerError %s", 500, payload)
}

func (o *PutRegisterClientIDInternalServerError) GetPayload() *models.Error {
	return o.Payload
}

func (o *PutRegisterClientIDInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPutRegisterClientIDDefault creates a PutRegisterClientIDDefault with default headers values
func NewPutRegisterClientIDDefault(code int) *PutRegisterClientIDDefault {
	return &PutRegisterClientIDDefault{
		_statusCode: code,
	}
}

/*
PutRegisterClientIDDefault describes a response with status code -1, with default header values.

Other error with any status code and response body format.
*/
type PutRegisterClientIDDefault struct {
	_statusCode int
}

// IsSuccess returns true when this put register client ID default response has a 2xx status code
func (o *PutRegisterClientIDDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this put register client ID default response has a 3xx status code
func (o *PutRegisterClientIDDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this put register client ID default response has a 4xx status code
func (o *PutRegisterClientIDDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this put register client ID default response has a 5xx status code
func (o *PutRegisterClientIDDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this put register client ID default response a status code equal to that given
func (o *PutRegisterClientIDDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the put register client ID default response
func (o *PutRegisterClientIDDefault) Code() int {
	return o._statusCode
}

func (o *PutRegisterClientIDDefault) Error() string {
	return fmt.Sprintf("[PUT /register/{client_id}][%d] PutRegisterClientID default", o._statusCode)
}

func (o *PutRegisterClientIDDefault) String() string {
	return fmt.Sprintf("[PUT /register/{client_id}][%d] PutRegisterClientID default", o._statusCode)
}

func (o *PutRegisterClientIDDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}