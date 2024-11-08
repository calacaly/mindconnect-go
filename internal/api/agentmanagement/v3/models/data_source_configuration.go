// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// DataSourceConfiguration data source configuration
//
// swagger:model DataSourceConfiguration
type DataSourceConfiguration struct {

	// Unique identifier of the datasource configuration.
	// Example: Configuration01
	// Required: true
	// Max Length: 36
	ConfigurationID *string `json:"configurationId"`

	// data sources
	// Required: true
	DataSources []*DataSource `json:"dataSources"`

	// e tag
	// Example: 2
	ETag string `json:"eTag,omitempty"`

	// id
	// Example: c3b7d31d-e966-46e6-9db1-d4b3e8c90d7b
	// Max Length: 36
	ID string `json:"id,omitempty"`
}

// Validate validates this data source configuration
func (m *DataSourceConfiguration) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateConfigurationID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDataSources(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DataSourceConfiguration) validateConfigurationID(formats strfmt.Registry) error {

	if err := validate.Required("configurationId", "body", m.ConfigurationID); err != nil {
		return err
	}

	if err := validate.MaxLength("configurationId", "body", *m.ConfigurationID, 36); err != nil {
		return err
	}

	return nil
}

func (m *DataSourceConfiguration) validateDataSources(formats strfmt.Registry) error {

	if err := validate.Required("dataSources", "body", m.DataSources); err != nil {
		return err
	}

	for i := 0; i < len(m.DataSources); i++ {
		if swag.IsZero(m.DataSources[i]) { // not required
			continue
		}

		if m.DataSources[i] != nil {
			if err := m.DataSources[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("dataSources" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("dataSources" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DataSourceConfiguration) validateID(formats strfmt.Registry) error {
	if swag.IsZero(m.ID) { // not required
		return nil
	}

	if err := validate.MaxLength("id", "body", m.ID, 36); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this data source configuration based on the context it is used
func (m *DataSourceConfiguration) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDataSources(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DataSourceConfiguration) contextValidateDataSources(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.DataSources); i++ {

		if m.DataSources[i] != nil {

			if swag.IsZero(m.DataSources[i]) { // not required
				return nil
			}

			if err := m.DataSources[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("dataSources" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("dataSources" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *DataSourceConfiguration) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DataSourceConfiguration) UnmarshalBinary(b []byte) error {
	var res DataSourceConfiguration
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
