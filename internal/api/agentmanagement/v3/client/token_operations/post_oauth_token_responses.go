// Code generated by go-swagger; DO NOT EDIT.

package token_operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/calacaly/mindconnect-go/internal/api/agentmanagement/v3/models"
)

// PostOauthTokenReader is a Reader for the PostOauthToken structure.
type PostOauthTokenReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostOauthTokenReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPostOauthTokenOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostOauthTokenBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewPostOauthTokenTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostOauthTokenInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		result := NewPostOauthTokenDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPostOauthTokenOK creates a PostOauthTokenOK with default headers values
func NewPostOauthTokenOK() *PostOauthTokenOK {
	return &PostOauthTokenOK{}
}

/*
PostOauthTokenOK describes a response with status code 200, with default header values.

OK
*/
type PostOauthTokenOK struct {

	/* Server time represented as epoch(unix) time in seconds.

	   Format: int64
	*/
	ServerTime int64

	Payload *models.AccessToken
}

// IsSuccess returns true when this post oauth token o k response has a 2xx status code
func (o *PostOauthTokenOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post oauth token o k response has a 3xx status code
func (o *PostOauthTokenOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post oauth token o k response has a 4xx status code
func (o *PostOauthTokenOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this post oauth token o k response has a 5xx status code
func (o *PostOauthTokenOK) IsServerError() bool {
	return false
}

// IsCode returns true when this post oauth token o k response a status code equal to that given
func (o *PostOauthTokenOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the post oauth token o k response
func (o *PostOauthTokenOK) Code() int {
	return 200
}

func (o *PostOauthTokenOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /oauth/token][%d] postOauthTokenOK %s", 200, payload)
}

func (o *PostOauthTokenOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /oauth/token][%d] postOauthTokenOK %s", 200, payload)
}

func (o *PostOauthTokenOK) GetPayload() *models.AccessToken {
	return o.Payload
}

func (o *PostOauthTokenOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header Server-Time
	hdrServerTime := response.GetHeader("Server-Time")

	if hdrServerTime != "" {
		valserverTime, err := swag.ConvertInt64(hdrServerTime)
		if err != nil {
			return errors.InvalidType("Server-Time", "header", "int64", hdrServerTime)
		}
		o.ServerTime = valserverTime
	}

	o.Payload = new(models.AccessToken)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostOauthTokenBadRequest creates a PostOauthTokenBadRequest with default headers values
func NewPostOauthTokenBadRequest() *PostOauthTokenBadRequest {
	return &PostOauthTokenBadRequest{}
}

/*
PostOauthTokenBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type PostOauthTokenBadRequest struct {

	/* Server time represented as epoch(unix) time in seconds.

	   Format: int64
	*/
	ServerTime int64

	Payload *models.BadrequestIAM
}

// IsSuccess returns true when this post oauth token bad request response has a 2xx status code
func (o *PostOauthTokenBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post oauth token bad request response has a 3xx status code
func (o *PostOauthTokenBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post oauth token bad request response has a 4xx status code
func (o *PostOauthTokenBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post oauth token bad request response has a 5xx status code
func (o *PostOauthTokenBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post oauth token bad request response a status code equal to that given
func (o *PostOauthTokenBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post oauth token bad request response
func (o *PostOauthTokenBadRequest) Code() int {
	return 400
}

func (o *PostOauthTokenBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /oauth/token][%d] postOauthTokenBadRequest %s", 400, payload)
}

func (o *PostOauthTokenBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /oauth/token][%d] postOauthTokenBadRequest %s", 400, payload)
}

func (o *PostOauthTokenBadRequest) GetPayload() *models.BadrequestIAM {
	return o.Payload
}

func (o *PostOauthTokenBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header Server-Time
	hdrServerTime := response.GetHeader("Server-Time")

	if hdrServerTime != "" {
		valserverTime, err := swag.ConvertInt64(hdrServerTime)
		if err != nil {
			return errors.InvalidType("Server-Time", "header", "int64", hdrServerTime)
		}
		o.ServerTime = valserverTime
	}

	o.Payload = new(models.BadrequestIAM)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostOauthTokenTooManyRequests creates a PostOauthTokenTooManyRequests with default headers values
func NewPostOauthTokenTooManyRequests() *PostOauthTokenTooManyRequests {
	return &PostOauthTokenTooManyRequests{}
}

/*
PostOauthTokenTooManyRequests describes a response with status code 429, with default header values.

API rate limit exceeded.
*/
type PostOauthTokenTooManyRequests struct {
	Payload *models.APIRateLimitExceeded
}

// IsSuccess returns true when this post oauth token too many requests response has a 2xx status code
func (o *PostOauthTokenTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post oauth token too many requests response has a 3xx status code
func (o *PostOauthTokenTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post oauth token too many requests response has a 4xx status code
func (o *PostOauthTokenTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this post oauth token too many requests response has a 5xx status code
func (o *PostOauthTokenTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this post oauth token too many requests response a status code equal to that given
func (o *PostOauthTokenTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the post oauth token too many requests response
func (o *PostOauthTokenTooManyRequests) Code() int {
	return 429
}

func (o *PostOauthTokenTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /oauth/token][%d] postOauthTokenTooManyRequests %s", 429, payload)
}

func (o *PostOauthTokenTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /oauth/token][%d] postOauthTokenTooManyRequests %s", 429, payload)
}

func (o *PostOauthTokenTooManyRequests) GetPayload() *models.APIRateLimitExceeded {
	return o.Payload
}

func (o *PostOauthTokenTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIRateLimitExceeded)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostOauthTokenInternalServerError creates a PostOauthTokenInternalServerError with default headers values
func NewPostOauthTokenInternalServerError() *PostOauthTokenInternalServerError {
	return &PostOauthTokenInternalServerError{}
}

/*
PostOauthTokenInternalServerError describes a response with status code 500, with default header values.

unexpected error
*/
type PostOauthTokenInternalServerError struct {
	Payload *models.Error
}

// IsSuccess returns true when this post oauth token internal server error response has a 2xx status code
func (o *PostOauthTokenInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post oauth token internal server error response has a 3xx status code
func (o *PostOauthTokenInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post oauth token internal server error response has a 4xx status code
func (o *PostOauthTokenInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post oauth token internal server error response has a 5xx status code
func (o *PostOauthTokenInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post oauth token internal server error response a status code equal to that given
func (o *PostOauthTokenInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post oauth token internal server error response
func (o *PostOauthTokenInternalServerError) Code() int {
	return 500
}

func (o *PostOauthTokenInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /oauth/token][%d] postOauthTokenInternalServerError %s", 500, payload)
}

func (o *PostOauthTokenInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /oauth/token][%d] postOauthTokenInternalServerError %s", 500, payload)
}

func (o *PostOauthTokenInternalServerError) GetPayload() *models.Error {
	return o.Payload
}

func (o *PostOauthTokenInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostOauthTokenDefault creates a PostOauthTokenDefault with default headers values
func NewPostOauthTokenDefault(code int) *PostOauthTokenDefault {
	return &PostOauthTokenDefault{
		_statusCode: code,
	}
}

/*
PostOauthTokenDefault describes a response with status code -1, with default header values.

Other error with any status code and response body format.
*/
type PostOauthTokenDefault struct {
	_statusCode int
}

// IsSuccess returns true when this post oauth token default response has a 2xx status code
func (o *PostOauthTokenDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this post oauth token default response has a 3xx status code
func (o *PostOauthTokenDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this post oauth token default response has a 4xx status code
func (o *PostOauthTokenDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this post oauth token default response has a 5xx status code
func (o *PostOauthTokenDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this post oauth token default response a status code equal to that given
func (o *PostOauthTokenDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the post oauth token default response
func (o *PostOauthTokenDefault) Code() int {
	return o._statusCode
}

func (o *PostOauthTokenDefault) Error() string {
	return fmt.Sprintf("[POST /oauth/token][%d] PostOauthToken default", o._statusCode)
}

func (o *PostOauthTokenDefault) String() string {
	return fmt.Sprintf("[POST /oauth/token][%d] PostOauthToken default", o._statusCode)
}

func (o *PostOauthTokenDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}