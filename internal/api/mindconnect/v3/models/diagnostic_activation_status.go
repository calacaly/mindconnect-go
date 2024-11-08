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

// DiagnosticActivationStatus diagnostic activation status
//
// swagger:model DiagnosticActivationStatus
type DiagnosticActivationStatus struct {

	// Status of the activation
	// Example: ACTIVE
	// Required: true
	// Enum: ["ACTIVE","INACTIVE"]
	Status *string `json:"status"`
}

// Validate validates this diagnostic activation status
func (m *DiagnosticActivationStatus) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateStatus(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var diagnosticActivationStatusTypeStatusPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["ACTIVE","INACTIVE"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		diagnosticActivationStatusTypeStatusPropEnum = append(diagnosticActivationStatusTypeStatusPropEnum, v)
	}
}

const (

	// DiagnosticActivationStatusStatusACTIVE captures enum value "ACTIVE"
	DiagnosticActivationStatusStatusACTIVE string = "ACTIVE"

	// DiagnosticActivationStatusStatusINACTIVE captures enum value "INACTIVE"
	DiagnosticActivationStatusStatusINACTIVE string = "INACTIVE"
)

// prop value enum
func (m *DiagnosticActivationStatus) validateStatusEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, diagnosticActivationStatusTypeStatusPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *DiagnosticActivationStatus) validateStatus(formats strfmt.Registry) error {

	if err := validate.Required("status", "body", m.Status); err != nil {
		return err
	}

	// value enum
	if err := m.validateStatusEnum("status", "body", *m.Status); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this diagnostic activation status based on context it is used
func (m *DiagnosticActivationStatus) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DiagnosticActivationStatus) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DiagnosticActivationStatus) UnmarshalBinary(b []byte) error {
	var res DiagnosticActivationStatus
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}