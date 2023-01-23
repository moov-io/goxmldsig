package dsig

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"

	"github.com/beevik/etree"
	"github.com/moov-io/goxmldsig/etreeutils"
)

type BahInfo struct {
	Head         *etree.Element
	body         *etree.Element
	keyInfo      *etree.Element
	Key          *rsa.PrivateKey
	UniqueDataId string
}

// Generate signInfo for the ISO 20022 Business Application Header
func (ctx *SigningContext) constructBahSignInfo(bahInfo *BahInfo) (*etree.Element, error) {
	// head signed info
	signedInfo, err := ctx.constructSignedInfo(bahInfo.Head, true)
	if err != nil {
		return nil, err
	}
	ref := signedInfo.FindElement(ReferenceTag)
	if ref != nil {
		ref.RemoveAttr(URIAttr)
		ref.CreateAttr(URIAttr, "")
	}

	// body signed info
	bodySignedInfo, err := ctx.constructSignedInfo(bahInfo.body, false)
	if err != nil {
		return nil, err
	}
	ref = bodySignedInfo.FindElement(ReferenceTag)
	if ref != nil {
		ref.RemoveAttr(URIAttr)
		ref.CreateAttr(URIAttr, "#"+bahInfo.UniqueDataId)
		signedInfo.Child = append(signedInfo.Child, ref)
	}

	if bahInfo.keyInfo == nil {
		return signedInfo, nil
	}

	// key info signed info
	keySignedInfo, err := ctx.constructSignedInfo(bahInfo.keyInfo, false)
	if err != nil {
		return nil, err
	}
	ref = keySignedInfo.FindElement(ReferenceTag)
	if ref != nil {
		ref.RemoveAttr(URIAttr)
		signedInfo.Child = append(signedInfo.Child, ref)
	}

	return signedInfo, nil
}

// Generate signature for the ISO 20022 Business Application Header
func (ctx *SigningContext) ConstructBahSignature(bahInfo *BahInfo) (*etree.Element, error) {

	// generate signInfo
	signedInfo, err := ctx.constructBahSignInfo(bahInfo)
	if err != nil {
		return nil, err
	}

	signature := &etree.Element{
		Tag:   SignatureTag,
		Space: ctx.Prefix,
	}

	xmlns := "xmlns"
	if ctx.Prefix != "" {
		xmlns += ":" + ctx.Prefix
	}

	signature.CreateAttr(xmlns, Namespace)
	signature.AddChild(signedInfo)
	if bahInfo.keyInfo != nil {
		signature.AddChild(bahInfo.keyInfo)
	}

	if bahInfo.Key == nil {
		return signature, nil
	}

	// When using xml-c14n11 (ie, non-exclusive canonicalization) the canonical form
	// of the SignedInfo must declare all namespaces that are in scope at it's final
	// enveloped location in the document. In order to do that, we're going to construct
	// a series of cascading NSContexts to capture namespace declarations:

	// First get the context surrounding the element we are signing.
	rootNSCtx, err := etreeutils.NSBuildParentContext(bahInfo.Head)
	if err != nil {
		return nil, err
	}

	// Then capture any declarations on the element itself.
	elNSCtx, err := rootNSCtx.SubContext(bahInfo.Head)
	if err != nil {
		return nil, err
	}

	// Followed by declarations on the Signature (which we just added above)
	sigNSCtx, err := elNSCtx.SubContext(signature)
	if err != nil {
		return nil, err
	}

	// Finally detach the SignedInfo in order to capture all of the namespace
	// declarations in the scope we've constructed.
	detachedSignedInfo, err := etreeutils.NSDetatch(sigNSCtx, signedInfo)
	if err != nil {
		return nil, err
	}

	digest, err := ctx.digest(detachedSignedInfo)
	if err != nil {
		return nil, err
	}

	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, bahInfo.Key, ctx.Hash, digest)
	if err != nil {
		return nil, err
	}

	signatureValue := ctx.createNamespacedElement(signature, SignatureValueTag)
	signatureValue.SetText(base64.StdEncoding.EncodeToString(rawSignature))

	return signature, nil
}

// Checking the ISO 20022 Business Application Header
func (ctx *SigningContext) BahChecking(el *etree.Element) (*etree.Element, *etree.Element, error) {
	var head, body *etree.Element
	for _, el := range el.ChildElements() {
		if el.Tag == ApplicationHeaderTag {
			if head == nil {
				head = el
			}
		} else {
			if body == nil {
				body = el
			}
		}
	}
	if head == nil || body == nil {
		return nil, nil, errors.New("the bah message should have a header and a document")
	}

	// strip Sgntr element
	sgntr := head.FindElement(ApplicationHeaderSgntrTag)
	if sgntr != nil {
		head.RemoveChild(sgntr)
	}

	return head, body, nil
}

// Singing the ISO 20022 Business Application Header
/*
func (ctx *SigningContext) BahSignEnveloped(el *etree.Element, uniqueDataId string) (*etree.Element, error) {

	// creating key info
	keyInfo := &etree.Element{
		Tag:   KeyInfoTag,
		Space: ctx.Prefix,
	}
	keyInfo.CreateAttr("Id", uniqueDataId)
	key, cert, err := ctx.KeyStore.GetKeyPair()
	if err != nil {
		return nil, err
	}

	certs := [][]byte{cert}
	if cs, ok := ctx.KeyStore.(X509ChainStore); ok {
		certs, err = cs.GetChain()
		if err != nil {
			return nil, err
		}
	}
	x509Data := ctx.createNamespacedElement(keyInfo, X509DataTag)
	for _, cert := range certs {
		x509Certificate := ctx.createNamespacedElement(x509Data, X509CertificateTag)
		x509Certificate.SetText(base64.StdEncoding.EncodeToString(cert))
	}

	head, body, err := ctx.BahChecking(el)
	if err != nil {
		return nil, err
	}

	signature, err := ctx.ConstructBahSignature(&BahInfo{
		Head:         head,
		body:         body,
		keyInfo:      keyInfo,
		Key:          key,
		UniqueDataId: uniqueDataId,
	})
	if err != nil {
		return nil, err
	}

	ret := el.Copy()
	head = ret.FindElement(ApplicationHeaderTag)
	sgntr := head.FindElement(ApplicationHeaderSgntrTag)
	if sgntr == nil {
		sgntr = &etree.Element{
			Tag:   ApplicationHeaderSgntrTag,
			Space: head.Space,
		}
		sgntr.Child = append(sgntr.Child, signature)
		head.Child = append(head.Child, sgntr)
	} else {
		sgntr.Child = []etree.Token{}
		sgntr.Child = append(sgntr.Child, signature)
	}

	return ret, nil
}
*/

func (ctx *SigningContext) BahSignEnveloped(el *etree.Element, uniqueDataId string) (*etree.Element, error) {

	// setting header sgntr tag
	head := el.FindElement(ApplicationHeaderTag)
	sgntr := head.FindElement(ApplicationHeaderSgntrTag)
	if sgntr == nil {
		sgntr = &etree.Element{
			Tag:   ApplicationHeaderSgntrTag,
			Space: "head",
		}
		head.Child = append(head.Child, sgntr)
	}

	sig, err := ctx.ConstructSignature(el, true)
	if err != nil {
		return nil, err
	}

	ret := el.Copy()

	//ret.Child = append(ret.Child, sig)
	head = ret.FindElement(ApplicationHeaderTag)
	sgntr = head.FindElement(ApplicationHeaderSgntrTag)

	if sgntr == nil {
		sgntr = &etree.Element{
			Tag:   "head:" + ApplicationHeaderSgntrTag,
			Space: head.Space,
		}
		sgntr.Child = append(sgntr.Child, sig)
		head.Child = append(head.Child, sgntr)
	} else {
		sgntr.Child = []etree.Token{}
		sgntr.Child = append(sgntr.Child, sig)
	}

	return ret, nil
}
