// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// NotSupported Operation on resource is not allowed for NATIVE_CA_CERTIFIED_X509 agents.
//
// swagger:model NotSupported
type NotSupported struct {

	// id
	ID string `json:"id,omitempty"`

	// message
	// Example: Offboard request is not supported for NATIVE_CA_CERTIFIED_X509 agents.
	Message string `json:"message,omitempty"`
}

// Validate validates this not supported
func (m *NotSupported) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this not supported based on context it is used
func (m *NotSupported) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *NotSupported) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *NotSupported) UnmarshalBinary(b []byte) error {
	var res NotSupported
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}