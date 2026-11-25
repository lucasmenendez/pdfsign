package pdfsign

import (
	"fmt"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/internal/acroform"
)

// resolveSignatureFieldID returns the object number of the terminal signature
// field with the given fully qualified name (12.7.3.2). The name is matched
// against the field tree exactly as the document defines it; a document may
// not hold two fields of the same fully qualified name, and the first match is
// returned.
func resolveSignatureFieldID(r *pdf.Reader, name string) (uint32, error) {
	if name == "" {
		return 0, fmt.Errorf("field name is empty")
	}

	var id uint32
	found := false
	acroform.Fields(r.Trailer().Key("Root"), func(f acroform.Field) bool {
		if found || f.Type != "Sig" || !f.Terminal || f.Name != name {
			return true
		}
		id, found = f.Dict.GetPtr().GetID(), true
		return false
	})
	if !found {
		return 0, fmt.Errorf("signature field %q not found", name)
	}

	return id, nil
}
