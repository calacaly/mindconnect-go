// Code generated by go-swagger; DO NOT EDIT.

package exchange

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

// PostExchangeReader is a Reader for the PostExchange structure.
type PostExchangeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostExchangeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPostExchangeOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostExchangeBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostExchangeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPostExchangeForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 413:
		result := NewPostExchangeRequestEntityTooLarge()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		result := NewPostExchangeDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPostExchangeOK creates a PostExchangeOK with default headers values
func NewPostExchangeOK() *PostExchangeOK {
	return &PostExchangeOK{}
}

/*
PostExchangeOK describes a response with status code 200, with default header values.

OK
*/
type PostExchangeOK struct {
}

// IsSuccess returns true when this post exchange o k response has a 2xx status code
func (o *PostExchangeOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post exchange o k response has a 3xx status code
func (o *PostExchangeOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post exchange o k response has a 4xx status code
func (o *PostExchangeOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this post exchange o k response has a 5xx status code
func (o *PostExchangeOK) IsServerError() bool {
	return false
}

// IsCode returns true when this post exchange o k response a status code equal to that given
func (o *PostExchangeOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the post exchange o k response
func (o *PostExchangeOK) Code() int {
	return 200
}

func (o *PostExchangeOK) Error() string {
	return fmt.Sprintf("[POST /exchange][%d] postExchangeOK", 200)
}

func (o *PostExchangeOK) String() string {
	return fmt.Sprintf("[POST /exchange][%d] postExchangeOK", 200)
}

func (o *PostExchangeOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewPostExchangeBadRequest creates a PostExchangeBadRequest with default headers values
func NewPostExchangeBadRequest() *PostExchangeBadRequest {
	return &PostExchangeBadRequest{}
}

/*
PostExchangeBadRequest describes a response with status code 400, with default header values.

bad request, e.g. multi part body is not well formatted.
*/
type PostExchangeBadRequest struct {
	Payload *models.Badrequest
}

// IsSuccess returns true when this post exchange bad request response has a 2xx status code
func (o *PostExchangeBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post exchange bad request response has a 3xx status code
func (o *PostExchangeBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post exchange bad request response has a 4xx status code
func (o *PostExchangeBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post exchange bad request response has a 5xx status code
func (o *PostExchangeBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post exchange bad request response a status code equal to that given
func (o *PostExchangeBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post exchange bad request response
func (o *PostExchangeBadRequest) Code() int {
	return 400
}

func (o *PostExchangeBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /exchange][%d] postExchangeBadRequest %s", 400, payload)
}

func (o *PostExchangeBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /exchange][%d] postExchangeBadRequest %s", 400, payload)
}

func (o *PostExchangeBadRequest) GetPayload() *models.Badrequest {
	return o.Payload
}

func (o *PostExchangeBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Badrequest)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostExchangeUnauthorized creates a PostExchangeUnauthorized with default headers values
func NewPostExchangeUnauthorized() *PostExchangeUnauthorized {
	return &PostExchangeUnauthorized{}
}

/*
PostExchangeUnauthorized describes a response with status code 401, with default header values.

unauthorized
*/
type PostExchangeUnauthorized struct {
	Payload *models.Unauthorized
}

// IsSuccess returns true when this post exchange unauthorized response has a 2xx status code
func (o *PostExchangeUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post exchange unauthorized response has a 3xx status code
func (o *PostExchangeUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post exchange unauthorized response has a 4xx status code
func (o *PostExchangeUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post exchange unauthorized response has a 5xx status code
func (o *PostExchangeUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post exchange unauthorized response a status code equal to that given
func (o *PostExchangeUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post exchange unauthorized response
func (o *PostExchangeUnauthorized) Code() int {
	return 401
}

func (o *PostExchangeUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /exchange][%d] postExchangeUnauthorized %s", 401, payload)
}

func (o *PostExchangeUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /exchange][%d] postExchangeUnauthorized %s", 401, payload)
}

func (o *PostExchangeUnauthorized) GetPayload() *models.Unauthorized {
	return o.Payload
}

func (o *PostExchangeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Unauthorized)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostExchangeForbidden creates a PostExchangeForbidden with default headers values
func NewPostExchangeForbidden() *PostExchangeForbidden {
	return &PostExchangeForbidden{}
}

/*
PostExchangeForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type PostExchangeForbidden struct {
	Payload *models.Forbidden
}

// IsSuccess returns true when this post exchange forbidden response has a 2xx status code
func (o *PostExchangeForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post exchange forbidden response has a 3xx status code
func (o *PostExchangeForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post exchange forbidden response has a 4xx status code
func (o *PostExchangeForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this post exchange forbidden response has a 5xx status code
func (o *PostExchangeForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this post exchange forbidden response a status code equal to that given
func (o *PostExchangeForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the post exchange forbidden response
func (o *PostExchangeForbidden) Code() int {
	return 403
}

func (o *PostExchangeForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /exchange][%d] postExchangeForbidden %s", 403, payload)
}

func (o *PostExchangeForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /exchange][%d] postExchangeForbidden %s", 403, payload)
}

func (o *PostExchangeForbidden) GetPayload() *models.Forbidden {
	return o.Payload
}

func (o *PostExchangeForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Forbidden)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostExchangeRequestEntityTooLarge creates a PostExchangeRequestEntityTooLarge with default headers values
func NewPostExchangeRequestEntityTooLarge() *PostExchangeRequestEntityTooLarge {
	return &PostExchangeRequestEntityTooLarge{}
}

/*
PostExchangeRequestEntityTooLarge describes a response with status code 413, with default header values.

Payload Too Large
*/
type PostExchangeRequestEntityTooLarge struct {
	Payload *models.PayLoadTooLarge
}

// IsSuccess returns true when this post exchange request entity too large response has a 2xx status code
func (o *PostExchangeRequestEntityTooLarge) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post exchange request entity too large response has a 3xx status code
func (o *PostExchangeRequestEntityTooLarge) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post exchange request entity too large response has a 4xx status code
func (o *PostExchangeRequestEntityTooLarge) IsClientError() bool {
	return true
}

// IsServerError returns true when this post exchange request entity too large response has a 5xx status code
func (o *PostExchangeRequestEntityTooLarge) IsServerError() bool {
	return false
}

// IsCode returns true when this post exchange request entity too large response a status code equal to that given
func (o *PostExchangeRequestEntityTooLarge) IsCode(code int) bool {
	return code == 413
}

// Code gets the status code for the post exchange request entity too large response
func (o *PostExchangeRequestEntityTooLarge) Code() int {
	return 413
}

func (o *PostExchangeRequestEntityTooLarge) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /exchange][%d] postExchangeRequestEntityTooLarge %s", 413, payload)
}

func (o *PostExchangeRequestEntityTooLarge) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /exchange][%d] postExchangeRequestEntityTooLarge %s", 413, payload)
}

func (o *PostExchangeRequestEntityTooLarge) GetPayload() *models.PayLoadTooLarge {
	return o.Payload
}

func (o *PostExchangeRequestEntityTooLarge) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PayLoadTooLarge)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostExchangeDefault creates a PostExchangeDefault with default headers values
func NewPostExchangeDefault(code int) *PostExchangeDefault {
	return &PostExchangeDefault{
		_statusCode: code,
	}
}

/*
PostExchangeDefault describes a response with status code -1, with default header values.

unexpected error
*/
type PostExchangeDefault struct {
	_statusCode int

	Payload *models.Error
}

// IsSuccess returns true when this post exchange default response has a 2xx status code
func (o *PostExchangeDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this post exchange default response has a 3xx status code
func (o *PostExchangeDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this post exchange default response has a 4xx status code
func (o *PostExchangeDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this post exchange default response has a 5xx status code
func (o *PostExchangeDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this post exchange default response a status code equal to that given
func (o *PostExchangeDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the post exchange default response
func (o *PostExchangeDefault) Code() int {
	return o._statusCode
}

func (o *PostExchangeDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /exchange][%d] PostExchange default %s", o._statusCode, payload)
}

func (o *PostExchangeDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /exchange][%d] PostExchange default %s", o._statusCode, payload)
}

func (o *PostExchangeDefault) GetPayload() *models.Error {
	return o.Payload
}

func (o *PostExchangeDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
