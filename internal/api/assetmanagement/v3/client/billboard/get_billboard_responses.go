// Code generated by go-swagger; DO NOT EDIT.

package billboard

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/calacaly/mindconnect-go/internal/api/assetmanagement/v3/models"
)

// GetBillboardReader is a Reader for the GetBillboard structure.
type GetBillboardReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetBillboardReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetBillboardOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /] getBillboard", response, response.Code())
	}
}

// NewGetBillboardOK creates a GetBillboardOK with default headers values
func NewGetBillboardOK() *GetBillboardOK {
	return &GetBillboardOK{}
}

/*
GetBillboardOK describes a response with status code 200, with default header values.

Array of links to available resources
*/
type GetBillboardOK struct {
	Payload *models.BillboardResource
}

// IsSuccess returns true when this get billboard o k response has a 2xx status code
func (o *GetBillboardOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get billboard o k response has a 3xx status code
func (o *GetBillboardOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get billboard o k response has a 4xx status code
func (o *GetBillboardOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get billboard o k response has a 5xx status code
func (o *GetBillboardOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get billboard o k response a status code equal to that given
func (o *GetBillboardOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get billboard o k response
func (o *GetBillboardOK) Code() int {
	return 200
}

func (o *GetBillboardOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /][%d] getBillboardOK %s", 200, payload)
}

func (o *GetBillboardOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /][%d] getBillboardOK %s", 200, payload)
}

func (o *GetBillboardOK) GetPayload() *models.BillboardResource {
	return o.Payload
}

func (o *GetBillboardOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BillboardResource)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}