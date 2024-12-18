// Code generated by go-swagger; DO NOT EDIT.

package token_operations

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

// GetOauthTokenKeyReader is a Reader for the GetOauthTokenKey structure.
type GetOauthTokenKeyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetOauthTokenKeyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetOauthTokenKeyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 304:
		result := NewGetOauthTokenKeyNotModified()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetOauthTokenKeyTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetOauthTokenKeyInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		result := NewGetOauthTokenKeyDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewGetOauthTokenKeyOK creates a GetOauthTokenKeyOK with default headers values
func NewGetOauthTokenKeyOK() *GetOauthTokenKeyOK {
	return &GetOauthTokenKeyOK{}
}

/*
GetOauthTokenKeyOK describes a response with status code 200, with default header values.

OK
*/
type GetOauthTokenKeyOK struct {
	Payload *models.TokenKey
}

// IsSuccess returns true when this get oauth token key o k response has a 2xx status code
func (o *GetOauthTokenKeyOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get oauth token key o k response has a 3xx status code
func (o *GetOauthTokenKeyOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get oauth token key o k response has a 4xx status code
func (o *GetOauthTokenKeyOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get oauth token key o k response has a 5xx status code
func (o *GetOauthTokenKeyOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get oauth token key o k response a status code equal to that given
func (o *GetOauthTokenKeyOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get oauth token key o k response
func (o *GetOauthTokenKeyOK) Code() int {
	return 200
}

func (o *GetOauthTokenKeyOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /oauth/token_key][%d] getOauthTokenKeyOK %s", 200, payload)
}

func (o *GetOauthTokenKeyOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /oauth/token_key][%d] getOauthTokenKeyOK %s", 200, payload)
}

func (o *GetOauthTokenKeyOK) GetPayload() *models.TokenKey {
	return o.Payload
}

func (o *GetOauthTokenKeyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.TokenKey)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOauthTokenKeyNotModified creates a GetOauthTokenKeyNotModified with default headers values
func NewGetOauthTokenKeyNotModified() *GetOauthTokenKeyNotModified {
	return &GetOauthTokenKeyNotModified{}
}

/*
GetOauthTokenKeyNotModified describes a response with status code 304, with default header values.

Not Modified
*/
type GetOauthTokenKeyNotModified struct {
}

// IsSuccess returns true when this get oauth token key not modified response has a 2xx status code
func (o *GetOauthTokenKeyNotModified) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get oauth token key not modified response has a 3xx status code
func (o *GetOauthTokenKeyNotModified) IsRedirect() bool {
	return true
}

// IsClientError returns true when this get oauth token key not modified response has a 4xx status code
func (o *GetOauthTokenKeyNotModified) IsClientError() bool {
	return false
}

// IsServerError returns true when this get oauth token key not modified response has a 5xx status code
func (o *GetOauthTokenKeyNotModified) IsServerError() bool {
	return false
}

// IsCode returns true when this get oauth token key not modified response a status code equal to that given
func (o *GetOauthTokenKeyNotModified) IsCode(code int) bool {
	return code == 304
}

// Code gets the status code for the get oauth token key not modified response
func (o *GetOauthTokenKeyNotModified) Code() int {
	return 304
}

func (o *GetOauthTokenKeyNotModified) Error() string {
	return fmt.Sprintf("[GET /oauth/token_key][%d] getOauthTokenKeyNotModified", 304)
}

func (o *GetOauthTokenKeyNotModified) String() string {
	return fmt.Sprintf("[GET /oauth/token_key][%d] getOauthTokenKeyNotModified", 304)
}

func (o *GetOauthTokenKeyNotModified) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetOauthTokenKeyTooManyRequests creates a GetOauthTokenKeyTooManyRequests with default headers values
func NewGetOauthTokenKeyTooManyRequests() *GetOauthTokenKeyTooManyRequests {
	return &GetOauthTokenKeyTooManyRequests{}
}

/*
GetOauthTokenKeyTooManyRequests describes a response with status code 429, with default header values.

API rate limit exceeded.
*/
type GetOauthTokenKeyTooManyRequests struct {
	Payload *models.APIRateLimitExceeded
}

// IsSuccess returns true when this get oauth token key too many requests response has a 2xx status code
func (o *GetOauthTokenKeyTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get oauth token key too many requests response has a 3xx status code
func (o *GetOauthTokenKeyTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get oauth token key too many requests response has a 4xx status code
func (o *GetOauthTokenKeyTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get oauth token key too many requests response has a 5xx status code
func (o *GetOauthTokenKeyTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get oauth token key too many requests response a status code equal to that given
func (o *GetOauthTokenKeyTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get oauth token key too many requests response
func (o *GetOauthTokenKeyTooManyRequests) Code() int {
	return 429
}

func (o *GetOauthTokenKeyTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /oauth/token_key][%d] getOauthTokenKeyTooManyRequests %s", 429, payload)
}

func (o *GetOauthTokenKeyTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /oauth/token_key][%d] getOauthTokenKeyTooManyRequests %s", 429, payload)
}

func (o *GetOauthTokenKeyTooManyRequests) GetPayload() *models.APIRateLimitExceeded {
	return o.Payload
}

func (o *GetOauthTokenKeyTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIRateLimitExceeded)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOauthTokenKeyInternalServerError creates a GetOauthTokenKeyInternalServerError with default headers values
func NewGetOauthTokenKeyInternalServerError() *GetOauthTokenKeyInternalServerError {
	return &GetOauthTokenKeyInternalServerError{}
}

/*
GetOauthTokenKeyInternalServerError describes a response with status code 500, with default header values.

unexpected error
*/
type GetOauthTokenKeyInternalServerError struct {
	Payload *models.Error
}

// IsSuccess returns true when this get oauth token key internal server error response has a 2xx status code
func (o *GetOauthTokenKeyInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get oauth token key internal server error response has a 3xx status code
func (o *GetOauthTokenKeyInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get oauth token key internal server error response has a 4xx status code
func (o *GetOauthTokenKeyInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get oauth token key internal server error response has a 5xx status code
func (o *GetOauthTokenKeyInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get oauth token key internal server error response a status code equal to that given
func (o *GetOauthTokenKeyInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get oauth token key internal server error response
func (o *GetOauthTokenKeyInternalServerError) Code() int {
	return 500
}

func (o *GetOauthTokenKeyInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /oauth/token_key][%d] getOauthTokenKeyInternalServerError %s", 500, payload)
}

func (o *GetOauthTokenKeyInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /oauth/token_key][%d] getOauthTokenKeyInternalServerError %s", 500, payload)
}

func (o *GetOauthTokenKeyInternalServerError) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOauthTokenKeyInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOauthTokenKeyDefault creates a GetOauthTokenKeyDefault with default headers values
func NewGetOauthTokenKeyDefault(code int) *GetOauthTokenKeyDefault {
	return &GetOauthTokenKeyDefault{
		_statusCode: code,
	}
}

/*
GetOauthTokenKeyDefault describes a response with status code -1, with default header values.

Other error with any status code and response body format.
*/
type GetOauthTokenKeyDefault struct {
	_statusCode int
}

// IsSuccess returns true when this get oauth token key default response has a 2xx status code
func (o *GetOauthTokenKeyDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this get oauth token key default response has a 3xx status code
func (o *GetOauthTokenKeyDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this get oauth token key default response has a 4xx status code
func (o *GetOauthTokenKeyDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this get oauth token key default response has a 5xx status code
func (o *GetOauthTokenKeyDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this get oauth token key default response a status code equal to that given
func (o *GetOauthTokenKeyDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the get oauth token key default response
func (o *GetOauthTokenKeyDefault) Code() int {
	return o._statusCode
}

func (o *GetOauthTokenKeyDefault) Error() string {
	return fmt.Sprintf("[GET /oauth/token_key][%d] GetOauthTokenKey default", o._statusCode)
}

func (o *GetOauthTokenKeyDefault) String() string {
	return fmt.Sprintf("[GET /oauth/token_key][%d] GetOauthTokenKey default", o._statusCode)
}

func (o *GetOauthTokenKeyDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
