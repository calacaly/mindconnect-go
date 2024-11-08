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

// PostDataPointMappingsReader is a Reader for the PostDataPointMappings structure.
type PostDataPointMappingsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostDataPointMappingsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPostDataPointMappingsCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostDataPointMappingsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostDataPointMappingsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPostDataPointMappingsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewPostDataPointMappingsConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		result := NewPostDataPointMappingsDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPostDataPointMappingsCreated creates a PostDataPointMappingsCreated with default headers values
func NewPostDataPointMappingsCreated() *PostDataPointMappingsCreated {
	return &PostDataPointMappingsCreated{}
}

/*
PostDataPointMappingsCreated describes a response with status code 201, with default header values.

Created
*/
type PostDataPointMappingsCreated struct {
	Payload *models.Mapping
}

// IsSuccess returns true when this post data point mappings created response has a 2xx status code
func (o *PostDataPointMappingsCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post data point mappings created response has a 3xx status code
func (o *PostDataPointMappingsCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post data point mappings created response has a 4xx status code
func (o *PostDataPointMappingsCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this post data point mappings created response has a 5xx status code
func (o *PostDataPointMappingsCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this post data point mappings created response a status code equal to that given
func (o *PostDataPointMappingsCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the post data point mappings created response
func (o *PostDataPointMappingsCreated) Code() int {
	return 201
}

func (o *PostDataPointMappingsCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /dataPointMappings][%d] postDataPointMappingsCreated %s", 201, payload)
}

func (o *PostDataPointMappingsCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /dataPointMappings][%d] postDataPointMappingsCreated %s", 201, payload)
}

func (o *PostDataPointMappingsCreated) GetPayload() *models.Mapping {
	return o.Payload
}

func (o *PostDataPointMappingsCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Mapping)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostDataPointMappingsBadRequest creates a PostDataPointMappingsBadRequest with default headers values
func NewPostDataPointMappingsBadRequest() *PostDataPointMappingsBadRequest {
	return &PostDataPointMappingsBadRequest{}
}

/*
PostDataPointMappingsBadRequest describes a response with status code 400, with default header values.

Bad Request. Request validations failed.
*/
type PostDataPointMappingsBadRequest struct {
	Payload *models.Badrequest
}

// IsSuccess returns true when this post data point mappings bad request response has a 2xx status code
func (o *PostDataPointMappingsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post data point mappings bad request response has a 3xx status code
func (o *PostDataPointMappingsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post data point mappings bad request response has a 4xx status code
func (o *PostDataPointMappingsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post data point mappings bad request response has a 5xx status code
func (o *PostDataPointMappingsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post data point mappings bad request response a status code equal to that given
func (o *PostDataPointMappingsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post data point mappings bad request response
func (o *PostDataPointMappingsBadRequest) Code() int {
	return 400
}

func (o *PostDataPointMappingsBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /dataPointMappings][%d] postDataPointMappingsBadRequest %s", 400, payload)
}

func (o *PostDataPointMappingsBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /dataPointMappings][%d] postDataPointMappingsBadRequest %s", 400, payload)
}

func (o *PostDataPointMappingsBadRequest) GetPayload() *models.Badrequest {
	return o.Payload
}

func (o *PostDataPointMappingsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Badrequest)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostDataPointMappingsUnauthorized creates a PostDataPointMappingsUnauthorized with default headers values
func NewPostDataPointMappingsUnauthorized() *PostDataPointMappingsUnauthorized {
	return &PostDataPointMappingsUnauthorized{}
}

/*
PostDataPointMappingsUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type PostDataPointMappingsUnauthorized struct {
	Payload *models.Unauthorized
}

// IsSuccess returns true when this post data point mappings unauthorized response has a 2xx status code
func (o *PostDataPointMappingsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post data point mappings unauthorized response has a 3xx status code
func (o *PostDataPointMappingsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post data point mappings unauthorized response has a 4xx status code
func (o *PostDataPointMappingsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post data point mappings unauthorized response has a 5xx status code
func (o *PostDataPointMappingsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post data point mappings unauthorized response a status code equal to that given
func (o *PostDataPointMappingsUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post data point mappings unauthorized response
func (o *PostDataPointMappingsUnauthorized) Code() int {
	return 401
}

func (o *PostDataPointMappingsUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /dataPointMappings][%d] postDataPointMappingsUnauthorized %s", 401, payload)
}

func (o *PostDataPointMappingsUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /dataPointMappings][%d] postDataPointMappingsUnauthorized %s", 401, payload)
}

func (o *PostDataPointMappingsUnauthorized) GetPayload() *models.Unauthorized {
	return o.Payload
}

func (o *PostDataPointMappingsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Unauthorized)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostDataPointMappingsForbidden creates a PostDataPointMappingsForbidden with default headers values
func NewPostDataPointMappingsForbidden() *PostDataPointMappingsForbidden {
	return &PostDataPointMappingsForbidden{}
}

/*
PostDataPointMappingsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type PostDataPointMappingsForbidden struct {
	Payload *models.Forbidden
}

// IsSuccess returns true when this post data point mappings forbidden response has a 2xx status code
func (o *PostDataPointMappingsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post data point mappings forbidden response has a 3xx status code
func (o *PostDataPointMappingsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post data point mappings forbidden response has a 4xx status code
func (o *PostDataPointMappingsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this post data point mappings forbidden response has a 5xx status code
func (o *PostDataPointMappingsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this post data point mappings forbidden response a status code equal to that given
func (o *PostDataPointMappingsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the post data point mappings forbidden response
func (o *PostDataPointMappingsForbidden) Code() int {
	return 403
}

func (o *PostDataPointMappingsForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /dataPointMappings][%d] postDataPointMappingsForbidden %s", 403, payload)
}

func (o *PostDataPointMappingsForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /dataPointMappings][%d] postDataPointMappingsForbidden %s", 403, payload)
}

func (o *PostDataPointMappingsForbidden) GetPayload() *models.Forbidden {
	return o.Payload
}

func (o *PostDataPointMappingsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Forbidden)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostDataPointMappingsConflict creates a PostDataPointMappingsConflict with default headers values
func NewPostDataPointMappingsConflict() *PostDataPointMappingsConflict {
	return &PostDataPointMappingsConflict{}
}

/*
PostDataPointMappingsConflict describes a response with status code 409, with default header values.

Conflict
*/
type PostDataPointMappingsConflict struct {
	Payload *models.Conflict
}

// IsSuccess returns true when this post data point mappings conflict response has a 2xx status code
func (o *PostDataPointMappingsConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post data point mappings conflict response has a 3xx status code
func (o *PostDataPointMappingsConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post data point mappings conflict response has a 4xx status code
func (o *PostDataPointMappingsConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this post data point mappings conflict response has a 5xx status code
func (o *PostDataPointMappingsConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this post data point mappings conflict response a status code equal to that given
func (o *PostDataPointMappingsConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the post data point mappings conflict response
func (o *PostDataPointMappingsConflict) Code() int {
	return 409
}

func (o *PostDataPointMappingsConflict) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /dataPointMappings][%d] postDataPointMappingsConflict %s", 409, payload)
}

func (o *PostDataPointMappingsConflict) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /dataPointMappings][%d] postDataPointMappingsConflict %s", 409, payload)
}

func (o *PostDataPointMappingsConflict) GetPayload() *models.Conflict {
	return o.Payload
}

func (o *PostDataPointMappingsConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Conflict)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostDataPointMappingsDefault creates a PostDataPointMappingsDefault with default headers values
func NewPostDataPointMappingsDefault(code int) *PostDataPointMappingsDefault {
	return &PostDataPointMappingsDefault{
		_statusCode: code,
	}
}

/*
PostDataPointMappingsDefault describes a response with status code -1, with default header values.

unexpected error
*/
type PostDataPointMappingsDefault struct {
	_statusCode int

	Payload *models.Error
}

// IsSuccess returns true when this post data point mappings default response has a 2xx status code
func (o *PostDataPointMappingsDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this post data point mappings default response has a 3xx status code
func (o *PostDataPointMappingsDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this post data point mappings default response has a 4xx status code
func (o *PostDataPointMappingsDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this post data point mappings default response has a 5xx status code
func (o *PostDataPointMappingsDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this post data point mappings default response a status code equal to that given
func (o *PostDataPointMappingsDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the post data point mappings default response
func (o *PostDataPointMappingsDefault) Code() int {
	return o._statusCode
}

func (o *PostDataPointMappingsDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /dataPointMappings][%d] PostDataPointMappings default %s", o._statusCode, payload)
}

func (o *PostDataPointMappingsDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /dataPointMappings][%d] PostDataPointMappings default %s", o._statusCode, payload)
}

func (o *PostDataPointMappingsDefault) GetPayload() *models.Error {
	return o.Payload
}

func (o *PostDataPointMappingsDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
