// Code generated by go-swagger; DO NOT EDIT.

package boarding_operations

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

// PostAgentsIDBoardingOffboardReader is a Reader for the PostAgentsIDBoardingOffboard structure.
type PostAgentsIDBoardingOffboardReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostAgentsIDBoardingOffboardReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPostAgentsIDBoardingOffboardOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostAgentsIDBoardingOffboardBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostAgentsIDBoardingOffboardUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPostAgentsIDBoardingOffboardForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewPostAgentsIDBoardingOffboardNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewPostAgentsIDBoardingOffboardConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewPostAgentsIDBoardingOffboardUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewPostAgentsIDBoardingOffboardTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostAgentsIDBoardingOffboardInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		result := NewPostAgentsIDBoardingOffboardDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPostAgentsIDBoardingOffboardOK creates a PostAgentsIDBoardingOffboardOK with default headers values
func NewPostAgentsIDBoardingOffboardOK() *PostAgentsIDBoardingOffboardOK {
	return &PostAgentsIDBoardingOffboardOK{}
}

/*
PostAgentsIDBoardingOffboardOK describes a response with status code 200, with default header values.

OK
*/
type PostAgentsIDBoardingOffboardOK struct {
	Payload *models.OnboardingStatus
}

// IsSuccess returns true when this post agents Id boarding offboard o k response has a 2xx status code
func (o *PostAgentsIDBoardingOffboardOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post agents Id boarding offboard o k response has a 3xx status code
func (o *PostAgentsIDBoardingOffboardOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post agents Id boarding offboard o k response has a 4xx status code
func (o *PostAgentsIDBoardingOffboardOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this post agents Id boarding offboard o k response has a 5xx status code
func (o *PostAgentsIDBoardingOffboardOK) IsServerError() bool {
	return false
}

// IsCode returns true when this post agents Id boarding offboard o k response a status code equal to that given
func (o *PostAgentsIDBoardingOffboardOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the post agents Id boarding offboard o k response
func (o *PostAgentsIDBoardingOffboardOK) Code() int {
	return 200
}

func (o *PostAgentsIDBoardingOffboardOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents/{id}/boarding/offboard][%d] postAgentsIdBoardingOffboardOK %s", 200, payload)
}

func (o *PostAgentsIDBoardingOffboardOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents/{id}/boarding/offboard][%d] postAgentsIdBoardingOffboardOK %s", 200, payload)
}

func (o *PostAgentsIDBoardingOffboardOK) GetPayload() *models.OnboardingStatus {
	return o.Payload
}

func (o *PostAgentsIDBoardingOffboardOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OnboardingStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAgentsIDBoardingOffboardBadRequest creates a PostAgentsIDBoardingOffboardBadRequest with default headers values
func NewPostAgentsIDBoardingOffboardBadRequest() *PostAgentsIDBoardingOffboardBadRequest {
	return &PostAgentsIDBoardingOffboardBadRequest{}
}

/*
PostAgentsIDBoardingOffboardBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type PostAgentsIDBoardingOffboardBadRequest struct {
	Payload *models.Badrequest
}

// IsSuccess returns true when this post agents Id boarding offboard bad request response has a 2xx status code
func (o *PostAgentsIDBoardingOffboardBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post agents Id boarding offboard bad request response has a 3xx status code
func (o *PostAgentsIDBoardingOffboardBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post agents Id boarding offboard bad request response has a 4xx status code
func (o *PostAgentsIDBoardingOffboardBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post agents Id boarding offboard bad request response has a 5xx status code
func (o *PostAgentsIDBoardingOffboardBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post agents Id boarding offboard bad request response a status code equal to that given
func (o *PostAgentsIDBoardingOffboardBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post agents Id boarding offboard bad request response
func (o *PostAgentsIDBoardingOffboardBadRequest) Code() int {
	return 400
}

func (o *PostAgentsIDBoardingOffboardBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents/{id}/boarding/offboard][%d] postAgentsIdBoardingOffboardBadRequest %s", 400, payload)
}

func (o *PostAgentsIDBoardingOffboardBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents/{id}/boarding/offboard][%d] postAgentsIdBoardingOffboardBadRequest %s", 400, payload)
}

func (o *PostAgentsIDBoardingOffboardBadRequest) GetPayload() *models.Badrequest {
	return o.Payload
}

func (o *PostAgentsIDBoardingOffboardBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Badrequest)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAgentsIDBoardingOffboardUnauthorized creates a PostAgentsIDBoardingOffboardUnauthorized with default headers values
func NewPostAgentsIDBoardingOffboardUnauthorized() *PostAgentsIDBoardingOffboardUnauthorized {
	return &PostAgentsIDBoardingOffboardUnauthorized{}
}

/*
PostAgentsIDBoardingOffboardUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type PostAgentsIDBoardingOffboardUnauthorized struct {
	Payload *models.Unauthorized
}

// IsSuccess returns true when this post agents Id boarding offboard unauthorized response has a 2xx status code
func (o *PostAgentsIDBoardingOffboardUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post agents Id boarding offboard unauthorized response has a 3xx status code
func (o *PostAgentsIDBoardingOffboardUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post agents Id boarding offboard unauthorized response has a 4xx status code
func (o *PostAgentsIDBoardingOffboardUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post agents Id boarding offboard unauthorized response has a 5xx status code
func (o *PostAgentsIDBoardingOffboardUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post agents Id boarding offboard unauthorized response a status code equal to that given
func (o *PostAgentsIDBoardingOffboardUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post agents Id boarding offboard unauthorized response
func (o *PostAgentsIDBoardingOffboardUnauthorized) Code() int {
	return 401
}

func (o *PostAgentsIDBoardingOffboardUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents/{id}/boarding/offboard][%d] postAgentsIdBoardingOffboardUnauthorized %s", 401, payload)
}

func (o *PostAgentsIDBoardingOffboardUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents/{id}/boarding/offboard][%d] postAgentsIdBoardingOffboardUnauthorized %s", 401, payload)
}

func (o *PostAgentsIDBoardingOffboardUnauthorized) GetPayload() *models.Unauthorized {
	return o.Payload
}

func (o *PostAgentsIDBoardingOffboardUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Unauthorized)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAgentsIDBoardingOffboardForbidden creates a PostAgentsIDBoardingOffboardForbidden with default headers values
func NewPostAgentsIDBoardingOffboardForbidden() *PostAgentsIDBoardingOffboardForbidden {
	return &PostAgentsIDBoardingOffboardForbidden{}
}

/*
PostAgentsIDBoardingOffboardForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type PostAgentsIDBoardingOffboardForbidden struct {
	Payload *models.Forbidden
}

// IsSuccess returns true when this post agents Id boarding offboard forbidden response has a 2xx status code
func (o *PostAgentsIDBoardingOffboardForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post agents Id boarding offboard forbidden response has a 3xx status code
func (o *PostAgentsIDBoardingOffboardForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post agents Id boarding offboard forbidden response has a 4xx status code
func (o *PostAgentsIDBoardingOffboardForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this post agents Id boarding offboard forbidden response has a 5xx status code
func (o *PostAgentsIDBoardingOffboardForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this post agents Id boarding offboard forbidden response a status code equal to that given
func (o *PostAgentsIDBoardingOffboardForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the post agents Id boarding offboard forbidden response
func (o *PostAgentsIDBoardingOffboardForbidden) Code() int {
	return 403
}

func (o *PostAgentsIDBoardingOffboardForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents/{id}/boarding/offboard][%d] postAgentsIdBoardingOffboardForbidden %s", 403, payload)
}

func (o *PostAgentsIDBoardingOffboardForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents/{id}/boarding/offboard][%d] postAgentsIdBoardingOffboardForbidden %s", 403, payload)
}

func (o *PostAgentsIDBoardingOffboardForbidden) GetPayload() *models.Forbidden {
	return o.Payload
}

func (o *PostAgentsIDBoardingOffboardForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Forbidden)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAgentsIDBoardingOffboardNotFound creates a PostAgentsIDBoardingOffboardNotFound with default headers values
func NewPostAgentsIDBoardingOffboardNotFound() *PostAgentsIDBoardingOffboardNotFound {
	return &PostAgentsIDBoardingOffboardNotFound{}
}

/*
PostAgentsIDBoardingOffboardNotFound describes a response with status code 404, with default header values.

Not Found
*/
type PostAgentsIDBoardingOffboardNotFound struct {
	Payload *models.Notfound
}

// IsSuccess returns true when this post agents Id boarding offboard not found response has a 2xx status code
func (o *PostAgentsIDBoardingOffboardNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post agents Id boarding offboard not found response has a 3xx status code
func (o *PostAgentsIDBoardingOffboardNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post agents Id boarding offboard not found response has a 4xx status code
func (o *PostAgentsIDBoardingOffboardNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this post agents Id boarding offboard not found response has a 5xx status code
func (o *PostAgentsIDBoardingOffboardNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this post agents Id boarding offboard not found response a status code equal to that given
func (o *PostAgentsIDBoardingOffboardNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the post agents Id boarding offboard not found response
func (o *PostAgentsIDBoardingOffboardNotFound) Code() int {
	return 404
}

func (o *PostAgentsIDBoardingOffboardNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents/{id}/boarding/offboard][%d] postAgentsIdBoardingOffboardNotFound %s", 404, payload)
}

func (o *PostAgentsIDBoardingOffboardNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents/{id}/boarding/offboard][%d] postAgentsIdBoardingOffboardNotFound %s", 404, payload)
}

func (o *PostAgentsIDBoardingOffboardNotFound) GetPayload() *models.Notfound {
	return o.Payload
}

func (o *PostAgentsIDBoardingOffboardNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Notfound)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAgentsIDBoardingOffboardConflict creates a PostAgentsIDBoardingOffboardConflict with default headers values
func NewPostAgentsIDBoardingOffboardConflict() *PostAgentsIDBoardingOffboardConflict {
	return &PostAgentsIDBoardingOffboardConflict{}
}

/*
PostAgentsIDBoardingOffboardConflict describes a response with status code 409, with default header values.

Resource in conflicting state.
*/
type PostAgentsIDBoardingOffboardConflict struct {
	Payload *models.Conflict
}

// IsSuccess returns true when this post agents Id boarding offboard conflict response has a 2xx status code
func (o *PostAgentsIDBoardingOffboardConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post agents Id boarding offboard conflict response has a 3xx status code
func (o *PostAgentsIDBoardingOffboardConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post agents Id boarding offboard conflict response has a 4xx status code
func (o *PostAgentsIDBoardingOffboardConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this post agents Id boarding offboard conflict response has a 5xx status code
func (o *PostAgentsIDBoardingOffboardConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this post agents Id boarding offboard conflict response a status code equal to that given
func (o *PostAgentsIDBoardingOffboardConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the post agents Id boarding offboard conflict response
func (o *PostAgentsIDBoardingOffboardConflict) Code() int {
	return 409
}

func (o *PostAgentsIDBoardingOffboardConflict) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents/{id}/boarding/offboard][%d] postAgentsIdBoardingOffboardConflict %s", 409, payload)
}

func (o *PostAgentsIDBoardingOffboardConflict) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents/{id}/boarding/offboard][%d] postAgentsIdBoardingOffboardConflict %s", 409, payload)
}

func (o *PostAgentsIDBoardingOffboardConflict) GetPayload() *models.Conflict {
	return o.Payload
}

func (o *PostAgentsIDBoardingOffboardConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Conflict)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAgentsIDBoardingOffboardUnprocessableEntity creates a PostAgentsIDBoardingOffboardUnprocessableEntity with default headers values
func NewPostAgentsIDBoardingOffboardUnprocessableEntity() *PostAgentsIDBoardingOffboardUnprocessableEntity {
	return &PostAgentsIDBoardingOffboardUnprocessableEntity{}
}

/*
PostAgentsIDBoardingOffboardUnprocessableEntity describes a response with status code 422, with default header values.

Not supported.
*/
type PostAgentsIDBoardingOffboardUnprocessableEntity struct {
	Payload *models.NotSupported
}

// IsSuccess returns true when this post agents Id boarding offboard unprocessable entity response has a 2xx status code
func (o *PostAgentsIDBoardingOffboardUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post agents Id boarding offboard unprocessable entity response has a 3xx status code
func (o *PostAgentsIDBoardingOffboardUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post agents Id boarding offboard unprocessable entity response has a 4xx status code
func (o *PostAgentsIDBoardingOffboardUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this post agents Id boarding offboard unprocessable entity response has a 5xx status code
func (o *PostAgentsIDBoardingOffboardUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this post agents Id boarding offboard unprocessable entity response a status code equal to that given
func (o *PostAgentsIDBoardingOffboardUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the post agents Id boarding offboard unprocessable entity response
func (o *PostAgentsIDBoardingOffboardUnprocessableEntity) Code() int {
	return 422
}

func (o *PostAgentsIDBoardingOffboardUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents/{id}/boarding/offboard][%d] postAgentsIdBoardingOffboardUnprocessableEntity %s", 422, payload)
}

func (o *PostAgentsIDBoardingOffboardUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents/{id}/boarding/offboard][%d] postAgentsIdBoardingOffboardUnprocessableEntity %s", 422, payload)
}

func (o *PostAgentsIDBoardingOffboardUnprocessableEntity) GetPayload() *models.NotSupported {
	return o.Payload
}

func (o *PostAgentsIDBoardingOffboardUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.NotSupported)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAgentsIDBoardingOffboardTooManyRequests creates a PostAgentsIDBoardingOffboardTooManyRequests with default headers values
func NewPostAgentsIDBoardingOffboardTooManyRequests() *PostAgentsIDBoardingOffboardTooManyRequests {
	return &PostAgentsIDBoardingOffboardTooManyRequests{}
}

/*
PostAgentsIDBoardingOffboardTooManyRequests describes a response with status code 429, with default header values.

API rate limit exceeded.
*/
type PostAgentsIDBoardingOffboardTooManyRequests struct {
	Payload *models.APIRateLimitExceeded
}

// IsSuccess returns true when this post agents Id boarding offboard too many requests response has a 2xx status code
func (o *PostAgentsIDBoardingOffboardTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post agents Id boarding offboard too many requests response has a 3xx status code
func (o *PostAgentsIDBoardingOffboardTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post agents Id boarding offboard too many requests response has a 4xx status code
func (o *PostAgentsIDBoardingOffboardTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this post agents Id boarding offboard too many requests response has a 5xx status code
func (o *PostAgentsIDBoardingOffboardTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this post agents Id boarding offboard too many requests response a status code equal to that given
func (o *PostAgentsIDBoardingOffboardTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the post agents Id boarding offboard too many requests response
func (o *PostAgentsIDBoardingOffboardTooManyRequests) Code() int {
	return 429
}

func (o *PostAgentsIDBoardingOffboardTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents/{id}/boarding/offboard][%d] postAgentsIdBoardingOffboardTooManyRequests %s", 429, payload)
}

func (o *PostAgentsIDBoardingOffboardTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents/{id}/boarding/offboard][%d] postAgentsIdBoardingOffboardTooManyRequests %s", 429, payload)
}

func (o *PostAgentsIDBoardingOffboardTooManyRequests) GetPayload() *models.APIRateLimitExceeded {
	return o.Payload
}

func (o *PostAgentsIDBoardingOffboardTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIRateLimitExceeded)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAgentsIDBoardingOffboardInternalServerError creates a PostAgentsIDBoardingOffboardInternalServerError with default headers values
func NewPostAgentsIDBoardingOffboardInternalServerError() *PostAgentsIDBoardingOffboardInternalServerError {
	return &PostAgentsIDBoardingOffboardInternalServerError{}
}

/*
PostAgentsIDBoardingOffboardInternalServerError describes a response with status code 500, with default header values.

unexpected error
*/
type PostAgentsIDBoardingOffboardInternalServerError struct {
	Payload *models.Error
}

// IsSuccess returns true when this post agents Id boarding offboard internal server error response has a 2xx status code
func (o *PostAgentsIDBoardingOffboardInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post agents Id boarding offboard internal server error response has a 3xx status code
func (o *PostAgentsIDBoardingOffboardInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post agents Id boarding offboard internal server error response has a 4xx status code
func (o *PostAgentsIDBoardingOffboardInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post agents Id boarding offboard internal server error response has a 5xx status code
func (o *PostAgentsIDBoardingOffboardInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post agents Id boarding offboard internal server error response a status code equal to that given
func (o *PostAgentsIDBoardingOffboardInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post agents Id boarding offboard internal server error response
func (o *PostAgentsIDBoardingOffboardInternalServerError) Code() int {
	return 500
}

func (o *PostAgentsIDBoardingOffboardInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents/{id}/boarding/offboard][%d] postAgentsIdBoardingOffboardInternalServerError %s", 500, payload)
}

func (o *PostAgentsIDBoardingOffboardInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents/{id}/boarding/offboard][%d] postAgentsIdBoardingOffboardInternalServerError %s", 500, payload)
}

func (o *PostAgentsIDBoardingOffboardInternalServerError) GetPayload() *models.Error {
	return o.Payload
}

func (o *PostAgentsIDBoardingOffboardInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAgentsIDBoardingOffboardDefault creates a PostAgentsIDBoardingOffboardDefault with default headers values
func NewPostAgentsIDBoardingOffboardDefault(code int) *PostAgentsIDBoardingOffboardDefault {
	return &PostAgentsIDBoardingOffboardDefault{
		_statusCode: code,
	}
}

/*
PostAgentsIDBoardingOffboardDefault describes a response with status code -1, with default header values.

Other error with any status code and response body format.
*/
type PostAgentsIDBoardingOffboardDefault struct {
	_statusCode int
}

// IsSuccess returns true when this post agents ID boarding offboard default response has a 2xx status code
func (o *PostAgentsIDBoardingOffboardDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this post agents ID boarding offboard default response has a 3xx status code
func (o *PostAgentsIDBoardingOffboardDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this post agents ID boarding offboard default response has a 4xx status code
func (o *PostAgentsIDBoardingOffboardDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this post agents ID boarding offboard default response has a 5xx status code
func (o *PostAgentsIDBoardingOffboardDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this post agents ID boarding offboard default response a status code equal to that given
func (o *PostAgentsIDBoardingOffboardDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the post agents ID boarding offboard default response
func (o *PostAgentsIDBoardingOffboardDefault) Code() int {
	return o._statusCode
}

func (o *PostAgentsIDBoardingOffboardDefault) Error() string {
	return fmt.Sprintf("[POST /agents/{id}/boarding/offboard][%d] PostAgentsIDBoardingOffboard default", o._statusCode)
}

func (o *PostAgentsIDBoardingOffboardDefault) String() string {
	return fmt.Sprintf("[POST /agents/{id}/boarding/offboard][%d] PostAgentsIDBoardingOffboard default", o._statusCode)
}

func (o *PostAgentsIDBoardingOffboardDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}