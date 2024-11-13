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

// FileMetadataResource file metadata resource
//
// swagger:model FileMetadataResource
type FileMetadataResource struct {

	// links
	Links *FileMetadataResourceLinks `json:"_links,omitempty"`

	// File description
	// Example: Company logo
	Description string `json:"description,omitempty"`

	// etag
	Etag ETag `json:"etag,omitempty"`

	// id
	ID UniqueID `json:"id,omitempty"`

	// Is the file used in any file assignment
	// Example: false
	IsAssigned bool `json:"isAssigned,omitempty"`

	// The time of the latest modification of the file
	// Format: date-time
	LastModified strfmt.DateTime `json:"lastModified,omitempty"`

	// File name given by the user
	// Example: logo
	Name string `json:"name,omitempty"`

	// Original filename of the file
	// Example: logo_small.png
	OriginalFileName string `json:"originalFileName,omitempty"`

	// The visibility of the file. PRIVATE hides files between subTenants and the t1Tenant's files from the subTenants. PUBLIC is visible for every user of the tenant.
	// Example: private
	// Enum: ["public","private"]
	Scope *string `json:"scope,omitempty"`

	// The id of the end-customer
	// Example: UnkarPlutt Inc.
	SubTenant string `json:"subTenant,omitempty"`

	// tenant Id
	TenantID TenantID `json:"tenantId,omitempty"`

	// The time of the file upload
	// Format: date-time
	Uploaded strfmt.DateTime `json:"uploaded,omitempty"`
}

// Validate validates this file metadata resource
func (m *FileMetadataResource) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateLinks(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEtag(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastModified(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScope(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTenantID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUploaded(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *FileMetadataResource) validateLinks(formats strfmt.Registry) error {
	if swag.IsZero(m.Links) { // not required
		return nil
	}

	if m.Links != nil {
		if err := m.Links.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_links")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("_links")
			}
			return err
		}
	}

	return nil
}

func (m *FileMetadataResource) validateEtag(formats strfmt.Registry) error {
	if swag.IsZero(m.Etag) { // not required
		return nil
	}

	if err := m.Etag.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("etag")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("etag")
		}
		return err
	}

	return nil
}

func (m *FileMetadataResource) validateID(formats strfmt.Registry) error {
	if swag.IsZero(m.ID) { // not required
		return nil
	}

	if err := m.ID.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("id")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("id")
		}
		return err
	}

	return nil
}

func (m *FileMetadataResource) validateLastModified(formats strfmt.Registry) error {
	if swag.IsZero(m.LastModified) { // not required
		return nil
	}

	if err := validate.FormatOf("lastModified", "body", "date-time", m.LastModified.String(), formats); err != nil {
		return err
	}

	return nil
}

var fileMetadataResourceTypeScopePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["public","private"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		fileMetadataResourceTypeScopePropEnum = append(fileMetadataResourceTypeScopePropEnum, v)
	}
}

const (

	// FileMetadataResourceScopePublic captures enum value "public"
	FileMetadataResourceScopePublic string = "public"

	// FileMetadataResourceScopePrivate captures enum value "private"
	FileMetadataResourceScopePrivate string = "private"
)

// prop value enum
func (m *FileMetadataResource) validateScopeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, fileMetadataResourceTypeScopePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *FileMetadataResource) validateScope(formats strfmt.Registry) error {
	if swag.IsZero(m.Scope) { // not required
		return nil
	}

	// value enum
	if err := m.validateScopeEnum("scope", "body", *m.Scope); err != nil {
		return err
	}

	return nil
}

func (m *FileMetadataResource) validateTenantID(formats strfmt.Registry) error {
	if swag.IsZero(m.TenantID) { // not required
		return nil
	}

	if err := m.TenantID.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("tenantId")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("tenantId")
		}
		return err
	}

	return nil
}

func (m *FileMetadataResource) validateUploaded(formats strfmt.Registry) error {
	if swag.IsZero(m.Uploaded) { // not required
		return nil
	}

	if err := validate.FormatOf("uploaded", "body", "date-time", m.Uploaded.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this file metadata resource based on the context it is used
func (m *FileMetadataResource) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateLinks(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateEtag(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateID(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTenantID(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *FileMetadataResource) contextValidateLinks(ctx context.Context, formats strfmt.Registry) error {

	if m.Links != nil {

		if swag.IsZero(m.Links) { // not required
			return nil
		}

		if err := m.Links.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_links")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("_links")
			}
			return err
		}
	}

	return nil
}

func (m *FileMetadataResource) contextValidateEtag(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Etag) { // not required
		return nil
	}

	if err := m.Etag.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("etag")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("etag")
		}
		return err
	}

	return nil
}

func (m *FileMetadataResource) contextValidateID(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.ID) { // not required
		return nil
	}

	if err := m.ID.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("id")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("id")
		}
		return err
	}

	return nil
}

func (m *FileMetadataResource) contextValidateTenantID(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.TenantID) { // not required
		return nil
	}

	if err := m.TenantID.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("tenantId")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("tenantId")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *FileMetadataResource) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *FileMetadataResource) UnmarshalBinary(b []byte) error {
	var res FileMetadataResource
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// FileMetadataResourceLinks file metadata resource links
//
// swagger:model FileMetadataResourceLinks
type FileMetadataResourceLinks struct {

	// download
	Download *FileMetadataResourceLinksDownload `json:"download,omitempty"`

	// self
	Self *RelSelf `json:"self,omitempty"`
}

// Validate validates this file metadata resource links
func (m *FileMetadataResourceLinks) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDownload(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSelf(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *FileMetadataResourceLinks) validateDownload(formats strfmt.Registry) error {
	if swag.IsZero(m.Download) { // not required
		return nil
	}

	if m.Download != nil {
		if err := m.Download.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_links" + "." + "download")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("_links" + "." + "download")
			}
			return err
		}
	}

	return nil
}

func (m *FileMetadataResourceLinks) validateSelf(formats strfmt.Registry) error {
	if swag.IsZero(m.Self) { // not required
		return nil
	}

	if m.Self != nil {
		if err := m.Self.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_links" + "." + "self")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("_links" + "." + "self")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this file metadata resource links based on the context it is used
func (m *FileMetadataResourceLinks) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDownload(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSelf(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *FileMetadataResourceLinks) contextValidateDownload(ctx context.Context, formats strfmt.Registry) error {

	if m.Download != nil {

		if swag.IsZero(m.Download) { // not required
			return nil
		}

		if err := m.Download.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_links" + "." + "download")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("_links" + "." + "download")
			}
			return err
		}
	}

	return nil
}

func (m *FileMetadataResourceLinks) contextValidateSelf(ctx context.Context, formats strfmt.Registry) error {

	if m.Self != nil {

		if swag.IsZero(m.Self) { // not required
			return nil
		}

		if err := m.Self.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("_links" + "." + "self")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("_links" + "." + "self")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *FileMetadataResourceLinks) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *FileMetadataResourceLinks) UnmarshalBinary(b []byte) error {
	var res FileMetadataResourceLinks
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// FileMetadataResourceLinksDownload link for downloading the file
//
// swagger:model FileMetadataResourceLinksDownload
type FileMetadataResourceLinksDownload struct {

	// href
	Href string `json:"href,omitempty"`
}

// Validate validates this file metadata resource links download
func (m *FileMetadataResourceLinksDownload) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this file metadata resource links download based on context it is used
func (m *FileMetadataResourceLinksDownload) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *FileMetadataResourceLinksDownload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *FileMetadataResourceLinksDownload) UnmarshalBinary(b []byte) error {
	var res FileMetadataResourceLinksDownload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
