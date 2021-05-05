package dsig

import (
	"crypto"
	"encoding/base64"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	randomKeyStore := RandomKeyStoreForTest()
	ctx := NewDefaultSigningContext(randomKeyStore)

	authnRequest := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}
	id := "_97e34c50-65ec-4132-8b39-02933960a96a"
	authnRequest.CreateAttr("ID", id)
	hash := crypto.SHA256.New()
	canonicalized, err := ctx.Canonicalizer.Canonicalize(authnRequest)
	require.NoError(t, err)

	_, err = hash.Write(canonicalized)
	require.NoError(t, err)
	digest := hash.Sum(nil)

	signed, err := ctx.SignEnveloped(authnRequest)
	require.NoError(t, err)
	require.NotEmpty(t, signed)

	sig := signed.FindElement("//" + SignatureTag)
	require.NotEmpty(t, sig)

	signedInfo := sig.FindElement("//" + SignedInfoTag)
	require.NotEmpty(t, signedInfo)

	canonicalizationMethodElement := signedInfo.FindElement("//" + CanonicalizationMethodTag)
	require.NotEmpty(t, canonicalizationMethodElement)

	canonicalizationMethodAttr := canonicalizationMethodElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, canonicalizationMethodAttr)
	require.Equal(t, CanonicalXML11AlgorithmId.String(), canonicalizationMethodAttr.Value)

	signatureMethodElement := signedInfo.FindElement("//" + SignatureMethodTag)
	require.NotEmpty(t, signatureMethodElement)

	signatureMethodAttr := signatureMethodElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, signatureMethodAttr)
	require.Equal(t, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", signatureMethodAttr.Value)

	referenceElement := signedInfo.FindElement("//" + ReferenceTag)
	require.NotEmpty(t, referenceElement)

	idAttr := referenceElement.SelectAttr(URIAttr)
	require.NotEmpty(t, idAttr)
	require.Equal(t, "#"+id, idAttr.Value)

	transformsElement := referenceElement.FindElement("//" + TransformsTag)
	require.NotEmpty(t, transformsElement)

	transformElement := transformsElement.FindElement("//" + TransformTag)
	require.NotEmpty(t, transformElement)

	algorithmAttr := transformElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, algorithmAttr)
	require.Equal(t, EnvelopedSignatureAltorithmId.String(), algorithmAttr.Value)

	digestMethodElement := referenceElement.FindElement("//" + DigestMethodTag)
	require.NotEmpty(t, digestMethodElement)

	digestMethodAttr := digestMethodElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, digestMethodElement)
	require.Equal(t, "http://www.w3.org/2001/04/xmlenc#sha256", digestMethodAttr.Value)

	digestValueElement := referenceElement.FindElement("//" + DigestValueTag)
	require.NotEmpty(t, digestValueElement)
	require.Equal(t, base64.StdEncoding.EncodeToString(digest), digestValueElement.Text())
}

func TestSignErrors(t *testing.T) {
	randomKeyStore := RandomKeyStoreForTest()
	ctx := &SigningContext{
		Hash:        crypto.SHA512_256,
		KeyStore:    randomKeyStore,
		IdAttribute: DefaultIdAttr,
		Prefix:      DefaultPrefix,
	}

	authnRequest := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}

	_, err := ctx.SignEnveloped(authnRequest)
	require.Error(t, err)
}

func TestSignNonDefaultID(t *testing.T) {
	// Sign a document by referencing a non-default ID attribute ("OtherID"),
	// and confirm that the signature correctly references it.
	ks := RandomKeyStoreForTest()
	ctx := &SigningContext{
		Hash:          crypto.SHA256,
		KeyStore:      ks,
		IdAttribute:   "OtherID",
		Prefix:        DefaultPrefix,
		Canonicalizer: MakeC14N11Canonicalizer(),
	}

	signable := &etree.Element{
		Space: "foo",
		Tag:   "Bar",
	}

	id := "_97e34c50-65ec-4132-8b39-02933960a96b"

	signable.CreateAttr("OtherID", id)
	signed, err := ctx.SignEnveloped(signable)
	require.NoError(t, err)

	ref := signed.FindElement("./Signature/SignedInfo/Reference")
	require.NotNil(t, ref)
	refURI := ref.SelectAttrValue("URI", "")
	require.Equal(t, refURI, "#"+id)
}

func TestBahSign(t *testing.T) {
	var messageBuf = `<Message xmlns="urn:tch" xmlns:head="urn:iso:std:iso:20022:tech:xsd:head.001.001.01" xmlns:ps="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10"><AppHdr><head:Fr><head:FIId><head:FinInstnId><head:ClrSysMmbId><head:MmbId>990000001S1</head:MmbId></head:ClrSysMmbId></head:FinInstnId></head:FIId></head:Fr><head:To><head:FIId><head:FinInstnId><head:ClrSysMmbId><head:MmbId>000000020C1</head:MmbId></head:ClrSysMmbId></head:FinInstnId></head:FIId></head:To><head:BizMsgIdr>B20190814990000001S1H00400000328351</head:BizMsgIdr><head:MsgDefIdr>pacs.002.001.10</head:MsgDefIdr><head:CreDt>2019-08-14T13:15:31</head:CreDt><head:Sgntr/></AppHdr><MessageStatusReport><ps:FIToFIPmtStsRpt xmlns:ps="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10"><ps:GrpHdr><ps:MsgId>M2019081400000000021B00000000395464</ps:MsgId><ps:CreDtTm>2019-08-14T13:16:04</ps:CreDtTm></ps:GrpHdr><ps:OrgnlGrpInfAndSts><ps:OrgnlMsgId>M20190814000000020C1B00000000395439</ps:OrgnlMsgId><ps:OrgnlMsgNmId>pain.013.001.07</ps:OrgnlMsgNmId><ps:OrgnlCreDtTm>2019-08-14T13:15:31</ps:OrgnlCreDtTm><ps:OrgnlNbOfTxs>1</ps:OrgnlNbOfTxs></ps:OrgnlGrpInfAndSts></ps:FIToFIPmtStsRpt></MessageStatusReport></Message>`
	randomKeyStore := RandomKeyStoreForTest()
	ctx := NewDefaultSigningContext(randomKeyStore)

	messageDoc := etree.NewDocument()
	err := messageDoc.ReadFromBytes([]byte(messageBuf))
	require.NoError(t, err)

	_, err = ctx.BahSignEnveloped(messageDoc.Root(), "UNIQUE_KEYINFO_ID")
	require.NoError(t, err)
}
