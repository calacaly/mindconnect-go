// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// EventMappingOptional event mapping optional
//
// swagger:model EventMappingOptional
type EventMappingOptional struct {

	// Unique identifier of the agent
	// Example: 11961bc396cd4a87a9b26b723f5b7ba0
	// Max Length: 32
	AgentID string `json:"agentId,omitempty"`

	// Unique identifier of the asset
	// Example: 2196dbc396cd4a87a9bd6b723fsb7baz
	// Max Length: 32
	AssetID string `json:"assetId,omitempty"`

	// e tag
	// Example: 1
	ETag string `json:"eTag,omitempty"`

	// Name of a field of the event type
	// Example: source
	// Max Length: 64
	EventTypeFieldName string `json:"eventTypeFieldName,omitempty"`

	// Value of the field of the event type
	//
	// Example: Machine_1
	// Max Length: 255
	EventTypeFieldValue string `json:"eventTypeFieldValue,omitempty"`

	// Unique identifier of the event type
	// Example: mytenant.connectivity.event.type.TestEventType
	// Max Length: 64
	EventTypeID string `json:"eventTypeId,omitempty"`

	// Name of event type
	// Example: TestEventType
	// Max Length: 64
	EventTypeName string `json:"eventTypeName,omitempty"`

	// Unique identifier of the mapping resource
	// Example: 2d94ba61-3e16-415c-a5c0-d428b8d92d42
	// Read Only: true
	// Max Length: 36
	// Format: uuid
	ID strfmt.UUID `json:"id,omitempty"`
}

// Validate validates this event mapping optional
func (m *EventMappingOptional) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAgentID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAssetID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEventTypeFieldName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEventTypeFieldValue(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEventTypeID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEventTypeName(formats); err != nil {
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

func (m *EventMappingOptional) validateAgentID(formats strfmt.Registry) error {
	if swag.IsZero(m.AgentID) { // not required
		return nil
	}

	if err := validate.MaxLength("agentId", "body", m.AgentID, 32); err != nil {
		return err
	}

	return nil
}

func (m *EventMappingOptional) validateAssetID(formats strfmt.Registry) error {
	if swag.IsZero(m.AssetID) { // not required
		return nil
	}

	if err := validate.MaxLength("assetId", "body", m.AssetID, 32); err != nil {
		return err
	}

	return nil
}

func (m *EventMappingOptional) validateEventTypeFieldName(formats strfmt.Registry) error {
	if swag.IsZero(m.EventTypeFieldName) { // not required
		return nil
	}

	if err := validate.MaxLength("eventTypeFieldName", "body", m.EventTypeFieldName, 64); err != nil {
		return err
	}

	return nil
}

func (m *EventMappingOptional) validateEventTypeFieldValue(formats strfmt.Registry) error {
	if swag.IsZero(m.EventTypeFieldValue) { // not required
		return nil
	}

	if err := validate.MaxLength("eventTypeFieldValue", "body", m.EventTypeFieldValue, 255); err != nil {
		return err
	}

	return nil
}

func (m *EventMappingOptional) validateEventTypeID(formats strfmt.Registry) error {
	if swag.IsZero(m.EventTypeID) { // not required
		return nil
	}

	if err := validate.MaxLength("eventTypeId", "body", m.EventTypeID, 64); err != nil {
		return err
	}

	return nil
}

func (m *EventMappingOptional) validateEventTypeName(formats strfmt.Registry) error {
	if swag.IsZero(m.EventTypeName) { // not required
		return nil
	}

	if err := validate.MaxLength("eventTypeName", "body", m.EventTypeName, 64); err != nil {
		return err
	}

	return nil
}

func (m *EventMappingOptional) validateID(formats strfmt.Registry) error {
	if swag.IsZero(m.ID) { // not required
		return nil
	}

	if err := validate.MaxLength("id", "body", m.ID.String(), 36); err != nil {
		return err
	}

	if err := validate.FormatOf("id", "body", "uuid", m.ID.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this event mapping optional based on the context it is used
func (m *EventMappingOptional) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateID(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *EventMappingOptional) contextValidateID(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "id", "body", strfmt.UUID(m.ID)); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *EventMappingOptional) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *EventMappingOptional) UnmarshalBinary(b []byte) error {
	var res EventMappingOptional
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}