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

// VariableDefinition variable definition
//
// swagger:model VariableDefinition
type VariableDefinition struct {
	VariableUpdate

	// Data type of the variable. BIG_STRING could only be used by variables in dynamic aspect-types. Cannot be changed.
	// Example: STRING
	// Required: true
	// Enum: ["BOOLEAN","INT","LONG","DOUBLE","STRING","TIMESTAMP","BIG_STRING"]
	DataType *string `json:"dataType"`

	// Indicates whether sorting and filtering is allowed on this variable. Only usable for static properties. Cannot be changed.
	// Example: true
	Searchable *bool `json:"searchable,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (m *VariableDefinition) UnmarshalJSON(raw []byte) error {
	// AO0
	var aO0 VariableUpdate
	if err := swag.ReadJSON(raw, &aO0); err != nil {
		return err
	}
	m.VariableUpdate = aO0

	// now for regular properties
	var propsVariableDefinition struct {
		DataType *string `json:"dataType"`

		Searchable *bool `json:"searchable,omitempty"`
	}
	if err := swag.ReadJSON(raw, &propsVariableDefinition); err != nil {
		return err
	}
	m.DataType = propsVariableDefinition.DataType

	m.Searchable = propsVariableDefinition.Searchable

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (m VariableDefinition) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 1)

	aO0, err := swag.WriteJSON(m.VariableUpdate)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, aO0)

	// now for regular properties
	var propsVariableDefinition struct {
		DataType *string `json:"dataType"`

		Searchable *bool `json:"searchable,omitempty"`
	}
	propsVariableDefinition.DataType = m.DataType

	propsVariableDefinition.Searchable = m.Searchable

	jsonDataPropsVariableDefinition, errVariableDefinition := swag.WriteJSON(propsVariableDefinition)
	if errVariableDefinition != nil {
		return nil, errVariableDefinition
	}
	_parts = append(_parts, jsonDataPropsVariableDefinition)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this variable definition
func (m *VariableDefinition) Validate(formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with VariableUpdate
	if err := m.VariableUpdate.Validate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDataType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var variableDefinitionTypeDataTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["BOOLEAN","INT","LONG","DOUBLE","STRING","TIMESTAMP","BIG_STRING"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		variableDefinitionTypeDataTypePropEnum = append(variableDefinitionTypeDataTypePropEnum, v)
	}
}

const (

	// VariableDefinitionDataTypeBOOLEAN captures enum value "BOOLEAN"
	VariableDefinitionDataTypeBOOLEAN string = "BOOLEAN"

	// VariableDefinitionDataTypeINT captures enum value "INT"
	VariableDefinitionDataTypeINT string = "INT"

	// VariableDefinitionDataTypeLONG captures enum value "LONG"
	VariableDefinitionDataTypeLONG string = "LONG"

	// VariableDefinitionDataTypeDOUBLE captures enum value "DOUBLE"
	VariableDefinitionDataTypeDOUBLE string = "DOUBLE"

	// VariableDefinitionDataTypeSTRING captures enum value "STRING"
	VariableDefinitionDataTypeSTRING string = "STRING"

	// VariableDefinitionDataTypeTIMESTAMP captures enum value "TIMESTAMP"
	VariableDefinitionDataTypeTIMESTAMP string = "TIMESTAMP"

	// VariableDefinitionDataTypeBIGSTRING captures enum value "BIG_STRING"
	VariableDefinitionDataTypeBIGSTRING string = "BIG_STRING"
)

// prop value enum
func (m *VariableDefinition) validateDataTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, variableDefinitionTypeDataTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *VariableDefinition) validateDataType(formats strfmt.Registry) error {

	if err := validate.Required("dataType", "body", m.DataType); err != nil {
		return err
	}

	// value enum
	if err := m.validateDataTypeEnum("dataType", "body", *m.DataType); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this variable definition based on the context it is used
func (m *VariableDefinition) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with VariableUpdate
	if err := m.VariableUpdate.ContextValidate(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// MarshalBinary interface implementation
func (m *VariableDefinition) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *VariableDefinition) UnmarshalBinary(b []byte) error {
	var res VariableDefinition
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
