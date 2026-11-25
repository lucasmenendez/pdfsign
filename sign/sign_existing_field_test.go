package sign_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pdf"
	pdfsign "github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/forms"
)

// newSelfSigned returns a fresh ECDSA P-256 identity with a self-signed
// certificate, as the signing tests sign with.
func newSelfSigned(t *testing.T, cn string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return key, cert
}

// buildTestPDF assembles a minimal one-page PDF whose AcroForm holds count
// pre-existing empty signature fields named presign_001..., each carrying the
// /Ff 2 required flag and a seed value dictionary, as a signing workflow that
// prepares fields up front would leave them.
func buildTestPDF(t *testing.T, count int) []byte {
	t.Helper()

	stream := "BT /F1 12 Tf 72 720 Td (Test document) Tj ET"
	objects := map[int]string{
		1: "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [" + fieldRefs(6, count) + "] >> >>",
		2: "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		3: "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
		4: fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream),
		5: "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("presign_%03d", i+1)
		objects[6+i] = fmt.Sprintf(
			"<< /Type /Annot /Subtype /Widget /FT /Sig /T (%s) /Ff 2 /Rect [0 0 0 0] /F 132"+
				" /SV << /Type /SeedValue /Ff 1 /Reason [(approval)] /Cert << /Ff 1 /Subject [<00112233FFEEDDCC>] >> >> >>", name)
	}
	maxID := 5 + count

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.5\n")
	offsets := make(map[int]int)
	for id := 1; id <= maxID; id++ {
		body, ok := objects[id]
		if !ok {
			t.Fatalf("object %d missing", id)
		}
		offsets[id] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", id, body)
	}
	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", maxID+1)
	buf.WriteString("0000000000 65535 f\r\n")
	for id := 1; id <= maxID; id++ {
		fmt.Fprintf(&buf, "%010d 00000 n\r\n", offsets[id])
	}
	fmt.Fprintf(&buf, "trailer << /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", maxID+1, xref)

	return buf.Bytes()
}

func fieldRefs(first, count int) string {
	refs := make([]string, count)
	for i := 0; i < count; i++ {
		refs[i] = fmt.Sprintf("%d 0 R", first+i)
	}
	return strings.Join(refs, " ")
}

func mustOpen(t *testing.T, b []byte) *pdfsign.Document {
	t.Helper()

	doc, err := pdfsign.Open(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("open document: %v", err)
	}
	return doc
}

// fieldDicts maps the fully qualified name of every form field to its
// dictionary.
func fieldDicts(t *testing.T, doc *pdfsign.Document) map[string]pdf.Value {
	t.Helper()

	m := make(map[string]pdf.Value)
	root := doc.Reader().Trailer().Key("Root")
	fields := root.Key("AcroForm").Key("Fields")
	for i := 0; fields.Kind() == pdf.Array && i < fields.Len(); i++ {
		forms.MapFields(fields.Index(i), "", m)
	}
	return m
}

// mustSign runs doc.Write and returns the signed bytes.
func mustSign(t *testing.T, doc *pdfsign.Document) []byte {
	t.Helper()

	var out bytes.Buffer
	if _, err := doc.Write(&out); err != nil {
		t.Fatalf("write signed document: %v", err)
	}
	return out.Bytes()
}

// mustVerify reports whether the document verifies, skipping revocation
// checks because the test PKI publishes none.
func mustVerify(t *testing.T, doc *pdfsign.Document) *pdfsign.VerifyBuilder {
	t.Helper()

	return doc.Verify().TrustSelfSigned(true).SkipRevocationCheck(true)
}

// byteRange returns the /ByteRange of a signature dictionary.
func byteRange(t *testing.T, sig pdf.Value) (int64, int64, int64, int64) {
	t.Helper()

	br := sig.Key("ByteRange")
	if br.Kind() != pdf.Array || br.Len() != 4 {
		t.Fatalf("byte range is not an array of four: %v", br)
	}
	return br.Index(0).Int64(), br.Index(1).Int64(), br.Index(2).Int64(), br.Index(3).Int64()
}

func TestSignIntoExistingField(t *testing.T) {
	original := buildTestPDF(t, 2)

	key, cert := newSelfSigned(t, "Test Signer")
	doc := mustOpen(t, original)
	doc.Sign(key, cert).
		Type(pdfsign.ApprovalSignature).
		Field("presign_001").
		Reason("approval")

	signed := mustSign(t, doc)
	if !bytes.HasPrefix(signed, original) {
		t.Fatal("signed document is not an incremental update of the original")
	}

	signedDoc := mustOpen(t, signed)

	// The field tree is unchanged: no new field was added.
	fields := fieldDicts(t, signedDoc)
	if len(fields) != 2 {
		t.Fatalf("field count changed, want 2, got %d", len(fields))
	}

	// The target field is signed and keeps the entries the preparer gave it.
	field := fields["presign_001"]
	sig := field.Key("V")
	if sig.IsNull() {
		t.Fatal("presign_001 carries no /V")
	}
	if got := field.Key("Ff").Int64(); got != 2 {
		t.Fatalf("presign_001 /Ff changed, want 2, got %d", got)
	}
	if field.Key("SV").IsNull() {
		t.Fatal("presign_001 lost its /SV seed value dictionary")
	}
	// The binary certificate whitelist survives the copy byte-exact.
	if got := field.Key("SV").Key("Cert").Key("Subject").Index(0).RawString(); got != "\x00\x11\x22\x33\xff\xee\xdd\xcc" {
		t.Fatalf("seed /Subject changed across the update: %q", got)
	}
	if sig.Key("Contents").IsNull() {
		t.Fatal("signature carries no /Contents")
	}

	// An approval signature locks nothing by default: a stray FieldMDP
	// transform would keep later signers from filling their own fields.
	if !sig.Key("Reference").IsNull() || !sig.Key("TransformMethod").IsNull() {
		t.Fatal("approval signature carries a field lock it was not given")
	}

	// The signature covers the whole file except its own /Contents.
	size := int64(len(signed))
	b0, b1, b2, b3 := byteRange(t, sig)
	if b0 != 0 || b2+b3 != size {
		t.Fatalf("byte range does not cover the file: [0 %d %d %d] of %d", b1, b2, b3, size)
	}

	// The second field remains unsigned.
	if !fields["presign_002"].Key("V").IsNull() {
		t.Fatal("presign_002 is signed")
	}

	// The signature verifies.
	if !mustVerify(t, signedDoc).Valid() {
		t.Fatal("signature did not verify")
	}
}

func TestCertifyIntoExistingField(t *testing.T) {
	original := buildTestPDF(t, 2)

	key, cert := newSelfSigned(t, "Test Author")
	doc := mustOpen(t, original)
	doc.Sign(key, cert).
		Type(pdfsign.CertificationSignature).
		Permission(pdfsign.AllowFormFilling).
		Field("presign_001")

	signed := mustSign(t, doc)
	signedDoc := mustOpen(t, signed)

	// The catalog /Perms entry names the certification signature.
	docmdp := signedDoc.Reader().Trailer().Key("Root").Key("Perms").Key("DocMDP")
	if docmdp.IsNull() {
		t.Fatal("catalog carries no /Perms /DocMDP")
	}
	ref := docmdp.Key("Reference")
	if ref.Kind() != pdf.Array || ref.Len() == 0 {
		t.Fatalf("certification signature carries no /Reference")
	}
	if got := ref.Index(0).Key("TransformMethod").Name(); got != "DocMDP" {
		t.Fatalf("transform method is %q, want DocMDP", got)
	}
	if got := ref.Index(0).Key("TransformParams").Key("P").Int64(); got != 2 {
		t.Fatalf("DocMDP permission is %d, want 2", got)
	}

	// The certification landed in the prepared field and added no new one.
	fields := fieldDicts(t, signedDoc)
	if len(fields) != 2 {
		t.Fatalf("field count changed, want 2, got %d", len(fields))
	}
	if fields["presign_001"].Key("V").IsNull() {
		t.Fatal("presign_001 carries no /V")
	}

	if !mustVerify(t, signedDoc).Valid() {
		t.Fatal("certification did not verify")
	}
}

func TestSequentialSignsIntoExistingFields(t *testing.T) {
	original := buildTestPDF(t, 2)

	key1, cert1 := newSelfSigned(t, "Test Signer One")
	key2, cert2 := newSelfSigned(t, "Test Signer Two")
	doc := mustOpen(t, original)
	doc.Sign(key1, cert1).Type(pdfsign.ApprovalSignature).Field("presign_001")
	doc.Sign(key2, cert2).Type(pdfsign.ApprovalSignature).Field("presign_002")

	signed := mustSign(t, doc)
	if !bytes.HasPrefix(signed, original) {
		t.Fatal("signed document is not an incremental update of the original")
	}

	signedDoc := mustOpen(t, signed)

	fields := fieldDicts(t, signedDoc)
	if len(fields) != 2 {
		t.Fatalf("field count changed, want 2, got %d", len(fields))
	}
	if fields["presign_001"].Key("V").IsNull() || fields["presign_002"].Key("V").IsNull() {
		t.Fatal("both prepared fields must be signed")
	}

	// Each signature covers its own revision: the first stops before the
	// second update's bytes, the second covers everything after it.
	size := int64(len(signed))
	_, b1, _, b3 := byteRange(t, fields["presign_001"].Key("V"))
	c0, _, c2, c3 := byteRange(t, fields["presign_002"].Key("V"))
	if b1+b3 >= size {
		t.Fatalf("first signature covers the whole file, want its own revision: %d+%d of %d", b1, b3, size)
	}
	if c0 != 0 || c2+c3 != size {
		t.Fatalf("second signature does not cover the file: %d + %d + %d of %d", c0, c2, c3, size)
	}

	vb := mustVerify(t, signedDoc)
	if !vb.Valid() {
		t.Fatal("sequential signatures did not verify")
	}
	if got := vb.Count(); got < 2 {
		t.Fatalf("verified %d signatures, want at least 2", got)
	}
}

func TestSignIntoMissingFieldFails(t *testing.T) {
	doc := mustOpen(t, buildTestPDF(t, 1))
	key, cert := newSelfSigned(t, "Test Signer")
	doc.Sign(key, cert).Type(pdfsign.ApprovalSignature).Field("presign_999")

	var out bytes.Buffer
	_, err := doc.Write(&out)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("want not-found error, got %v", err)
	}
}

func TestSignIntoSignedFieldFails(t *testing.T) {
	original := buildTestPDF(t, 1)

	key, cert := newSelfSigned(t, "Test Signer")
	firstDoc := mustOpen(t, original)
	firstDoc.Sign(key, cert).Type(pdfsign.ApprovalSignature).Field("presign_001")
	first := mustSign(t, firstDoc)

	// A second signer cannot claim the same field.
	secondDoc := mustOpen(t, first)
	key2, cert2 := newSelfSigned(t, "Test Signer Two")
	secondDoc.Sign(key2, cert2).Type(pdfsign.ApprovalSignature).Field("presign_001")

	var out bytes.Buffer
	if _, err := secondDoc.Write(&out); err == nil || !strings.Contains(err.Error(), "already signed") {
		t.Fatalf("want already-signed error, got %v", err)
	}
}

func TestApprovalFieldLock(t *testing.T) {
	original := buildTestPDF(t, 2)

	key, cert := newSelfSigned(t, "Test Signer")
	doc := mustOpen(t, original)
	doc.Sign(key, cert).
		Type(pdfsign.ApprovalSignature).
		Field("presign_001").
		LockFields("Include", "presign_001").
		Reason("approval")

	signed := mustSign(t, doc)
	signedDoc := mustOpen(t, signed)

	sig := fieldDicts(t, signedDoc)["presign_001"].Key("V")
	ref := sig.Key("Reference")
	if ref.Kind() != pdf.Array || ref.Len() != 1 {
		t.Fatalf("locked signature carries no /Reference array: %v", ref)
	}
	sigRef := ref.Index(0)
	if got := sigRef.Key("TransformMethod").Name(); got != "FieldMDP" {
		t.Fatalf("transform method is %q, want FieldMDP", got)
	}
	params := sigRef.Key("TransformParams")
	if got := params.Key("Action").Name(); got != "Include" {
		t.Fatalf("lock action is %q, want Include", got)
	}
	locked := params.Key("Fields")
	if locked.Kind() != pdf.Array || locked.Len() != 1 || locked.Index(0).Text() != "presign_001" {
		t.Fatalf("locked fields are %v, want [presign_001]", locked)
	}

	if !mustVerify(t, signedDoc).Valid() {
		t.Fatal("locked signature did not verify")
	}
}

func TestFieldLockValidation(t *testing.T) {
	cases := []struct {
		name    string
		action  string
		fields  []string
		sigType pdfsign.SignatureType
		wantErr string
	}{
		{"unknown action", "Everything", nil, pdfsign.ApprovalSignature, "not All, Include or Exclude"},
		{"include without fields", "Include", nil, pdfsign.ApprovalSignature, "needs the fields it names"},
		{"all with fields", "All", []string{"presign_001"}, pdfsign.ApprovalSignature, "names no fields"},
		{"lock on certification", "All", nil, pdfsign.CertificationSignature, "only valid on an approval signature"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, cert := newSelfSigned(t, "Test Signer")
			doc := mustOpen(t, buildTestPDF(t, 1))
			sb := doc.Sign(key, cert).Type(tc.sigType).LockFields(tc.action, tc.fields...)
			if tc.sigType == pdfsign.CertificationSignature {
				sb.Permission(pdfsign.AllowFormFilling)
			} else {
				sb.Field("presign_001")
			}

			var out bytes.Buffer
			_, err := doc.Write(&out)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestVisibleAppearanceWithExistingFieldFails(t *testing.T) {
	doc := mustOpen(t, buildTestPDF(t, 1))
	key, cert := newSelfSigned(t, "Test Signer")
	doc.Sign(key, cert).
		Type(pdfsign.ApprovalSignature).
		Field("presign_001").
		Appearance(pdfsign.NewAppearance(100, 50), 10, 10)

	var out bytes.Buffer
	if _, err := doc.Write(&out); err == nil || !strings.Contains(err.Error(), "visible appearance") {
		t.Fatalf("want visible-appearance error, got %v", err)
	}
}
