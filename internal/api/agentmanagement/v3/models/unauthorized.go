// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// Unauthorized unauthorized
//
// swagger:model Unauthorized
type Unauthorized struct {

	// id
	ID string `json:"id,omitempty"`

	// message
	// Example: Not authorized to access this resource.
	Message string `json:"message,omitempty"`
}

// Validate validates this unauthorized
func (m *Unauthorized) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this unauthorized based on context it is used
func (m *Unauthorized) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *Unauthorized) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Unauthorized) UnmarshalBinary(b []byte) error {
	var res Unauthorized
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
