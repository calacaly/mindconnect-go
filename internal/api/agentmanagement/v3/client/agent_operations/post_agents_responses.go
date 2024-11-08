// Code generated by go-swagger; DO NOT EDIT.

package agent_operations

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

// PostAgentsReader is a Reader for the PostAgents structure.
type PostAgentsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostAgentsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPostAgentsCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostAgentsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostAgentsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPostAgentsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewPostAgentsConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewPostAgentsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostAgentsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		result := NewPostAgentsDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPostAgentsCreated creates a PostAgentsCreated with default headers values
func NewPostAgentsCreated() *PostAgentsCreated {
	return &PostAgentsCreated{}
}

/*
PostAgentsCreated describes a response with status code 201, with default header values.

Created
*/
type PostAgentsCreated struct {
	Payload *models.Agent
}

// IsSuccess returns true when this post agents created response has a 2xx status code
func (o *PostAgentsCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post agents created response has a 3xx status code
func (o *PostAgentsCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post agents created response has a 4xx status code
func (o *PostAgentsCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this post agents created response has a 5xx status code
func (o *PostAgentsCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this post agents created response a status code equal to that given
func (o *PostAgentsCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the post agents created response
func (o *PostAgentsCreated) Code() int {
	return 201
}

func (o *PostAgentsCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents][%d] postAgentsCreated %s", 201, payload)
}

func (o *PostAgentsCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents][%d] postAgentsCreated %s", 201, payload)
}

func (o *PostAgentsCreated) GetPayload() *models.Agent {
	return o.Payload
}

func (o *PostAgentsCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Agent)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAgentsBadRequest creates a PostAgentsBadRequest with default headers values
func NewPostAgentsBadRequest() *PostAgentsBadRequest {
	return &PostAgentsBadRequest{}
}

/*
PostAgentsBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type PostAgentsBadRequest struct {
	Payload *models.Badrequest
}

// IsSuccess returns true when this post agents bad request response has a 2xx status code
func (o *PostAgentsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post agents bad request response has a 3xx status code
func (o *PostAgentsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post agents bad request response has a 4xx status code
func (o *PostAgentsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post agents bad request response has a 5xx status code
func (o *PostAgentsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post agents bad request response a status code equal to that given
func (o *PostAgentsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post agents bad request response
func (o *PostAgentsBadRequest) Code() int {
	return 400
}

func (o *PostAgentsBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents][%d] postAgentsBadRequest %s", 400, payload)
}

func (o *PostAgentsBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents][%d] postAgentsBadRequest %s", 400, payload)
}

func (o *PostAgentsBadRequest) GetPayload() *models.Badrequest {
	return o.Payload
}

func (o *PostAgentsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Badrequest)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAgentsUnauthorized creates a PostAgentsUnauthorized with default headers values
func NewPostAgentsUnauthorized() *PostAgentsUnauthorized {
	return &PostAgentsUnauthorized{}
}

/*
PostAgentsUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type PostAgentsUnauthorized struct {
	Payload *models.Unauthorized
}

// IsSuccess returns true when this post agents unauthorized response has a 2xx status code
func (o *PostAgentsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post agents unauthorized response has a 3xx status code
func (o *PostAgentsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post agents unauthorized response has a 4xx status code
func (o *PostAgentsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post agents unauthorized response has a 5xx status code
func (o *PostAgentsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post agents unauthorized response a status code equal to that given
func (o *PostAgentsUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post agents unauthorized response
func (o *PostAgentsUnauthorized) Code() int {
	return 401
}

func (o *PostAgentsUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents][%d] postAgentsUnauthorized %s", 401, payload)
}

func (o *PostAgentsUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents][%d] postAgentsUnauthorized %s", 401, payload)
}

func (o *PostAgentsUnauthorized) GetPayload() *models.Unauthorized {
	return o.Payload
}

func (o *PostAgentsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Unauthorized)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAgentsForbidden creates a PostAgentsForbidden with default headers values
func NewPostAgentsForbidden() *PostAgentsForbidden {
	return &PostAgentsForbidden{}
}

/*
PostAgentsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type PostAgentsForbidden struct {
	Payload *models.Forbidden
}

// IsSuccess returns true when this post agents forbidden response has a 2xx status code
func (o *PostAgentsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post agents forbidden response has a 3xx status code
func (o *PostAgentsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post agents forbidden response has a 4xx status code
func (o *PostAgentsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this post agents forbidden response has a 5xx status code
func (o *PostAgentsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this post agents forbidden response a status code equal to that given
func (o *PostAgentsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the post agents forbidden response
func (o *PostAgentsForbidden) Code() int {
	return 403
}

func (o *PostAgentsForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents][%d] postAgentsForbidden %s", 403, payload)
}

func (o *PostAgentsForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents][%d] postAgentsForbidden %s", 403, payload)
}

func (o *PostAgentsForbidden) GetPayload() *models.Forbidden {
	return o.Payload
}

func (o *PostAgentsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Forbidden)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAgentsConflict creates a PostAgentsConflict with default headers values
func NewPostAgentsConflict() *PostAgentsConflict {
	return &PostAgentsConflict{}
}

/*
PostAgentsConflict describes a response with status code 409, with default header values.

Resource is already available.
*/
type PostAgentsConflict struct {
	Payload *models.Conflict
}

// IsSuccess returns true when this post agents conflict response has a 2xx status code
func (o *PostAgentsConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post agents conflict response has a 3xx status code
func (o *PostAgentsConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post agents conflict response has a 4xx status code
func (o *PostAgentsConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this post agents conflict response has a 5xx status code
func (o *PostAgentsConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this post agents conflict response a status code equal to that given
func (o *PostAgentsConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the post agents conflict response
func (o *PostAgentsConflict) Code() int {
	return 409
}

func (o *PostAgentsConflict) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents][%d] postAgentsConflict %s", 409, payload)
}

func (o *PostAgentsConflict) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents][%d] postAgentsConflict %s", 409, payload)
}

func (o *PostAgentsConflict) GetPayload() *models.Conflict {
	return o.Payload
}

func (o *PostAgentsConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Conflict)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAgentsTooManyRequests creates a PostAgentsTooManyRequests with default headers values
func NewPostAgentsTooManyRequests() *PostAgentsTooManyRequests {
	return &PostAgentsTooManyRequests{}
}

/*
PostAgentsTooManyRequests describes a response with status code 429, with default header values.

API rate limit exceeded.
*/
type PostAgentsTooManyRequests struct {
	Payload *models.APIRateLimitExceeded
}

// IsSuccess returns true when this post agents too many requests response has a 2xx status code
func (o *PostAgentsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post agents too many requests response has a 3xx status code
func (o *PostAgentsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post agents too many requests response has a 4xx status code
func (o *PostAgentsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this post agents too many requests response has a 5xx status code
func (o *PostAgentsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this post agents too many requests response a status code equal to that given
func (o *PostAgentsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the post agents too many requests response
func (o *PostAgentsTooManyRequests) Code() int {
	return 429
}

func (o *PostAgentsTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents][%d] postAgentsTooManyRequests %s", 429, payload)
}

func (o *PostAgentsTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents][%d] postAgentsTooManyRequests %s", 429, payload)
}

func (o *PostAgentsTooManyRequests) GetPayload() *models.APIRateLimitExceeded {
	return o.Payload
}

func (o *PostAgentsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIRateLimitExceeded)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAgentsInternalServerError creates a PostAgentsInternalServerError with default headers values
func NewPostAgentsInternalServerError() *PostAgentsInternalServerError {
	return &PostAgentsInternalServerError{}
}

/*
PostAgentsInternalServerError describes a response with status code 500, with default header values.

unexpected error
*/
type PostAgentsInternalServerError struct {
	Payload *models.Error
}

// IsSuccess returns true when this post agents internal server error response has a 2xx status code
func (o *PostAgentsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post agents internal server error response has a 3xx status code
func (o *PostAgentsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post agents internal server error response has a 4xx status code
func (o *PostAgentsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post agents internal server error response has a 5xx status code
func (o *PostAgentsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post agents internal server error response a status code equal to that given
func (o *PostAgentsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post agents internal server error response
func (o *PostAgentsInternalServerError) Code() int {
	return 500
}

func (o *PostAgentsInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents][%d] postAgentsInternalServerError %s", 500, payload)
}

func (o *PostAgentsInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /agents][%d] postAgentsInternalServerError %s", 500, payload)
}

func (o *PostAgentsInternalServerError) GetPayload() *models.Error {
	return o.Payload
}

func (o *PostAgentsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAgentsDefault creates a PostAgentsDefault with default headers values
func NewPostAgentsDefault(code int) *PostAgentsDefault {
	return &PostAgentsDefault{
		_statusCode: code,
	}
}

/*
PostAgentsDefault describes a response with status code -1, with default header values.

Other error with any status code and response body format.
*/
type PostAgentsDefault struct {
	_statusCode int
}

// IsSuccess returns true when this post agents default response has a 2xx status code
func (o *PostAgentsDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this post agents default response has a 3xx status code
func (o *PostAgentsDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this post agents default response has a 4xx status code
func (o *PostAgentsDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this post agents default response has a 5xx status code
func (o *PostAgentsDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this post agents default response a status code equal to that given
func (o *PostAgentsDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the post agents default response
func (o *PostAgentsDefault) Code() int {
	return o._statusCode
}

func (o *PostAgentsDefault) Error() string {
	return fmt.Sprintf("[POST /agents][%d] PostAgents default", o._statusCode)
}

func (o *PostAgentsDefault) String() string {
	return fmt.Sprintf("[POST /agents][%d] PostAgents default", o._statusCode)
}

func (o *PostAgentsDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}