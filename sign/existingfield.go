package sign

import (
	"bytes"
	"fmt"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/internal/acroform"
)

// signIntoExistingField signs into the pre-existing signature field identified
// by SignData.TargetFieldID instead of creating a new widget field: the field
// keeps the entries the preparer gave it — its name, flags and seed values —
// and its /V is set to the new signature object. No field is added to the
// AcroForm, so a document prepared with named signature fields keeps the exact
// field tree the preparer defined.
//
// The field must be a signature field the form tree reaches and must carry no
// /V. A field already signed is refused: replacing its value would leave the
// earlier signature unreferenced and misreport who signed.
func (context *SignContext) signIntoExistingField() error {
	if context.SignData.Appearance.Visible {
		return fmt.Errorf("sign: a visible appearance is not supported when signing into an existing field")
	}

	var target pdf.Value
	found := false
	acroform.SignatureFields(context.PDFReader.Trailer().Key("Root"), func(field pdf.Value) bool {
		if !found && field.GetPtr().GetID() == context.SignData.TargetFieldID {
			target, found = field, true
			return false
		}
		return true
	})
	if !found {
		return fmt.Errorf("sign: field %d is not a signature field the form tree reaches", context.SignData.TargetFieldID)
	}
	if !target.Key("V").IsNull() {
		return fmt.Errorf("sign: field %d is already signed", context.SignData.TargetFieldID)
	}

	content, err := buildTargetFieldUpdate(target, context.SignData.objectId)
	if err != nil {
		return err
	}

	return context.UpdateObject(context.SignData.TargetFieldID, content)
}

// buildTargetFieldUpdate builds the replacement dictionary of the target
// field: every entry the field holds except /V — an indirect entry stays a
// reference, so a parent or resource is neither duplicated nor turned into a
// copy — with /V set to the signature object.
func buildTargetFieldUpdate(field pdf.Value, signatureObjectID uint32) ([]byte, error) {
	ptr := field.GetPtr()
	if ptr.GetID() == 0 {
		return nil, fmt.Errorf("sign: target field is a direct object")
	}

	var buf bytes.Buffer
	buf.WriteString("<<\n")
	for _, key := range field.Keys() {
		if key == "V" {
			continue // replaced below with the new signature object
		}
		entry := field.Key(key)
		if entryPtr := entry.GetPtr(); entryPtr != ptr && entryPtr.GetID() > 0 {
			fmt.Fprintf(&buf, "  /%s %d %d R\n", key, entryPtr.GetID(), entryPtr.GetGen())
			continue
		}
		fmt.Fprintf(&buf, "  /%s %s\n", key, entry.String())
	}
	fmt.Fprintf(&buf, "  /V %d 0 R\n", signatureObjectID)
	buf.WriteString(">>")

	return buf.Bytes(), nil
}
