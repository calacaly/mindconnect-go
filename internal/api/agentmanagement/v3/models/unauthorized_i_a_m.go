// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// UnauthorizedIAM unauthorized i a m
//
// swagger:model UnauthorizedIAM
type UnauthorizedIAM struct {

	// error
	// Example: token_validation_failed
	Error string `json:"error,omitempty"`

	// An error message with Correlation-ID value.
	// Example: [d6270fa4-f8f2-46d7-8370-1fbcacb37c52] Token validation failed.
	ErrorDescription string `json:"error_description,omitempty"`

	// id
	ID string `json:"id,omitempty"`
}

// Validate validates this unauthorized i a m
func (m *UnauthorizedIAM) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this unauthorized i a m based on context it is used
func (m *UnauthorizedIAM) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *UnauthorizedIAM) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UnauthorizedIAM) UnmarshalBinary(b []byte) error {
	var res UnauthorizedIAM
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
