// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// UpdateAgentRequest update agent request
//
// swagger:model UpdateAgentRequest
type UpdateAgentRequest struct {

	// Name must be unique per tenant.
	// Example: Nanobox Agent
	// Required: true
	// Max Length: 128
	Name *string `json:"name"`

	// security profile
	// Required: true
	// Enum: ["SHARED_SECRET","RSA_3072"]
	SecurityProfile *string `json:"securityProfile"`
}

// Validate validates this update agent request
func (m *UpdateAgentRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSecurityProfile(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UpdateAgentRequest) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	if err := validate.MaxLength("name", "body", *m.Name, 128); err != nil {
		return err
	}

	return nil
}

var updateAgentRequestTypeSecurityProfilePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["SHARED_SECRET","RSA_3072"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		updateAgentRequestTypeSecurityProfilePropEnum = append(updateAgentRequestTypeSecurityProfilePropEnum, v)
	}
}

const (

	// UpdateAgentRequestSecurityProfileSHAREDSECRET captures enum value "SHARED_SECRET"
	UpdateAgentRequestSecurityProfileSHAREDSECRET string = "SHARED_SECRET"

	// UpdateAgentRequestSecurityProfileRSA3072 captures enum value "RSA_3072"
	UpdateAgentRequestSecurityProfileRSA3072 string = "RSA_3072"
)

// prop value enum
func (m *UpdateAgentRequest) validateSecurityProfileEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, updateAgentRequestTypeSecurityProfilePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *UpdateAgentRequest) validateSecurityProfile(formats strfmt.Registry) error {

	if err := validate.Required("securityProfile", "body", m.SecurityProfile); err != nil {
		return err
	}

	// value enum
	if err := m.validateSecurityProfileEnum("securityProfile", "body", *m.SecurityProfile); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this update agent request based on context it is used
func (m *UpdateAgentRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *UpdateAgentRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UpdateAgentRequest) UnmarshalBinary(b []byte) error {
	var res UpdateAgentRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
