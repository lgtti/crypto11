package crypto11

import (
	"github.com/miekg/pkcs11"
	"maps"
	"slices"
)

func (c *Context) Unwrap(wrappingKeyAlias string, wrappedKey []byte, attributes AttributeSet) error {
	wrappingKey, err := c.FindKey(nil, []byte(wrappingKeyAlias))
	if err != nil {
		return err
	}
	return c.withSession(func(session *pkcs11Session) error {
		_, err = session.ctx.UnwrapKey(
			session.handle,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP, nil)},
			wrappingKey.handle,
			wrappedKey,
			slices.Collect(maps.Values(attributes)),
		)
		return err
	})
}
