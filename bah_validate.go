package dsig

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"reflect"

	"github.com/beevik/etree"
	"github.com/moov-io/goxmldsig/types"
)

type BahValidateInfo struct {
	El        *etree.Element
	Signature *types.Signature
	NewRefs   []types.Reference
	Cert      *x509.Certificate
}

// Verify untrusted certificate
func (ctx *ValidationContext) verifyUntrustedCertificate(sig *types.Signature) (*x509.Certificate, error) {
	now := ctx.Clock.Now()

	roots, err := ctx.CertificateStore.Certificates()
	if err != nil {
		return nil, err
	}

	var cert *x509.Certificate

	if sig.KeyInfo != nil {
		// If the Signature includes KeyInfo, extract the certificate from there
		if len(sig.KeyInfo.X509Data.X509Certificates) > 0 && sig.KeyInfo.X509Data.X509Certificates[0].Data != "" {
			certData, err := base64.StdEncoding.DecodeString(
				whiteSpace.ReplaceAllString(sig.KeyInfo.X509Data.X509Certificates[0].Data, ""))
			if err != nil {
				return nil, errors.New("Failed to parse certificate")
			}

			cert, err = x509.ParseCertificate(certData)
		} else {
			cert, err = ctx.findCertificateWithX509Data(sig.KeyInfo.X509Data)
		}

		if err != nil {
			return nil, err
		}

		if cert == nil {
			return nil, errors.New("missing X509Certificate within KeyInfo")
		}

	} else {
		// If the Signature doesn't have KeyInfo, Use the root certificate if there is only one
		if len(roots) == 1 {
			cert = roots[0]
		} else {
			return nil, errors.New("Missing x509 Element")
		}
	}

	// Verify that the certificate is one we trust
	// if !contains(roots, cert) {
	// 	return nil, errors.New("Could not verify certificate against trusted certs")
	// }

	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, errors.New("Cert is not valid at this time")
	}

	return cert, nil
}

// Validate signature of the ISO 20022 Business Application Header
func (ctx *ValidationContext) validateBahSignature(validateInfo *BahValidateInfo) (*etree.Element, error) {

	var ref *types.Reference

	// Find the first reference which references the top-level element
	for _, _ref := range validateInfo.Signature.SignedInfo.References {
		find := false
		for _, _newRef := range validateInfo.NewRefs {
			if reflect.DeepEqual(_ref, _newRef) {
				find = true
				break
			}
		}
		if !find {
			return nil, errors.New("don't match original references and new references")
		}
	}

	// Find the first reference which references the top-level element
	for _, _ref := range validateInfo.Signature.SignedInfo.References {
		if _ref.URI == "" && ref == nil {
			ref = &_ref
		}
		if validateInfo.Signature.KeyInfo != nil && len(_ref.URI) > 1 && _ref.URI[1:] == validateInfo.Signature.KeyInfo.Id {
			ref = &_ref
		}
	}

	// Perform all transformations listed in the 'SignedInfo'
	// Basically, this means removing the 'SignedInfo'
	transformed, canonicalizer, err := ctx.transform(validateInfo.El, validateInfo.Signature, ref)
	if err != nil {
		return nil, err
	}

	// Decode the 'SignatureValue' so we can compare against it
	decodedSignature, err := base64.StdEncoding.DecodeString(validateInfo.Signature.SignatureValue.Data)
	if err != nil {
		return nil, errors.New("Could not decode signature")
	}

	// Actually verify the 'SignedInfo' was signed by a trusted source
	signatureMethod := validateInfo.Signature.SignedInfo.SignatureMethod.Algorithm
	err = ctx.verifySignedInfo(validateInfo.Signature, canonicalizer, signatureMethod, validateInfo.Cert, decodedSignature)
	if err != nil {
		return nil, err
	}

	return transformed, nil
}

// Finding references of the ISO 20022 Business Application Header
func (ctx *ValidationContext) findReferences(el *etree.Element, key *types.KeyInfo) ([]types.Reference, error) {

	// find keyInfo
	keyInfo := el.FindElement(ApplicationHeaderTag + "/" + ApplicationHeaderSgntrTag + "/" + SignatureTag + "/" + KeyInfoTag)

	dummyCtx := NewDefaultSigningContext(RandomKeyStoreForTest())
	head, body, err := dummyCtx.BahChecking(el)
	if err != nil {
		return nil, err
	}

	// generate signature without sign
	newSig, err := dummyCtx.ConstructBahSignature(&BahInfo{
		Head:         head,
		body:         body,
		keyInfo:      keyInfo,
		Key:          nil,
		UniqueDataId: key.Id,
	})
	if err != nil {
		return nil, err
	}

	// convert *etree.Element to []types.Reference
	doc := etree.NewDocument()
	doc.SetRoot(newSig)
	signBuf, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}

	var sig types.Signature
	err = xml.Unmarshal(signBuf, &sig)
	if err != nil {
		return nil, err
	}

	if sig.SignedInfo == nil {
		return nil, errors.New("don't generate signed info from message")
	}

	return sig.SignedInfo.References, nil
}

func (ctx *ValidationContext) BahValidate(el *etree.Element) (*etree.Element, bool, error) {

	trusted := false

	// Make a copy of the element to avoid mutating the one we were passed.
	el = el.Copy()

	sig, err := ctx.findSignature(el)
	if err != nil {
		return nil, trusted, err
	}

	cert, err := ctx.verifyCertificate(sig)
	if err != nil {
		cert, err = ctx.verifyUntrustedCertificate(sig)
		if err != nil {
			return nil, false, err
		}
	} else {
		trusted = true
	}

	elm, err := ctx.validateSignature(el, sig, cert)
	return elm, trusted, err
}
