package crypto11

import (
	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

func (c *Context) Wrap(wrappingKeyAlias string, keyAlias string) ([]byte, AttributeSet, error) {
	wrappingKey, err := c.FindKey(nil, []byte(wrappingKeyAlias))
	if err != nil {
		return nil, nil, err
	}
	pairs, err := c.FindKeyPairs(nil, []byte(keyAlias))
	if err != nil || len(pairs) == 0 {
		return nil, nil, err
	}

	signerHandle, err := c.SignerHandle(pairs[0])
	if err != nil {
		return nil, nil, err
	}

	attributes, err := c.GetAttributes(pairs[0], []AttributeType{pkcs11.CKA_TOKEN, pkcs11.CKA_SIGN, pkcs11.CKA_LABEL, pkcs11.CKA_SENSITIVE, pkcs11.CKA_EXTRACTABLE, pkcs11.CKA_PRIVATE, pkcs11.CKA_UNWRAP, pkcs11.CKA_CLASS, pkcs11.CKA_KEY_TYPE})
	if err != nil {
		return nil, nil, err
	}

	var wrappedKey []byte
	err = c.withSession(func(session *pkcs11Session) error {
		wKey, err := session.ctx.WrapKey(
			session.handle,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP, nil)},
			wrappingKey.pkcs11Object.handle,
			signerHandle)
		wrappedKey = wKey
		if err != nil {
			return err
		}
		return nil
	})
	return wrappedKey, attributes, err
}

func (c *Context) SignerHandle(signer Signer) (pkcs11.ObjectHandle, error) {
	var handle pkcs11.ObjectHandle
	switch k := (signer).(type) {
	case *pkcs11PrivateKeyDSA:
		handle = k.handle
	case *pkcs11PrivateKeyRSA:
		handle = k.handle
	case *pkcs11PrivateKeyECDSA:
		handle = k.handle
	default:
		return 0, errors.Errorf("not a PKCS#11 asymmetric key")
	}
	return handle, nil
}

func (c *Context) FindPrivateKeyHandle(id []byte, label []byte) (privateKeyHandles []pkcs11.ObjectHandle, err error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	if id == nil && label == nil {
		return nil, errors.New("id and label cannot both be nil")
	}

	attributes := NewAttributeSet()

	if id != nil {
		err = attributes.Set(CkaId, id)
		if err != nil {
			return nil, err
		}
	}
	if label != nil {
		err = attributes.Set(CkaLabel, label)
		if err != nil {
			return nil, err
		}
	}

	err = c.withSession(func(session *pkcs11Session) error {
		// Add the private key class to the template to find the private half
		privAttributes := attributes.Copy()
		err = privAttributes.Set(CkaClass, pkcs11.CKO_PRIVATE_KEY)
		if err != nil {
			return err
		}

		privateKeyHandles, err = findKeysWithAttributes(session, privAttributes.ToSlice())
		if err != nil {
			return err
		}

		return nil
	})
	return privateKeyHandles, nil
}
