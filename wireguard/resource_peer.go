package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/terraform/helper/schema"
	"golang.org/x/crypto/curve25519"
)

func resourcePeer() *schema.Resource {
	return &schema.Resource{
		Create: CreatePeer,
		Read:   RepopulateKeys,
		Delete: schema.RemoveFromState,
		Importer: &schema.ResourceImporter{
			State: ImportPeer,
		},

		Schema: map[string]*schema.Schema{
			"keepers": {
				Type:     schema.TypeMap,
				Optional: true,
				ForceNew: true,
			},

			"private": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"public": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func CreatePeer(d *schema.ResourceData, meta interface{}) error {
	bytes := make([]byte, 32)

	n, err := rand.Reader.Read(bytes)
	if n != 32 {
		return errors.New("generated insufficient random bytes")
	}
	if err != nil {
		return errwrap.Wrapf("error generating random bytes: {{err}}", err)
	}

	bytes[0] &= 248
	bytes[31] &= 127
	bytes[31] |= 64

	b64Str := base64.RawURLEncoding.EncodeToString(bytes)
	d.SetId(b64Str)

	return RepopulateKeys(d, meta)
}

func RepopulateKeys(d *schema.ResourceData, _ interface{}) error {
	base64Str := d.Id()

	bytes, err := base64.RawURLEncoding.DecodeString(base64Str)
	if err != nil {
		return errwrap.Wrapf("Error decoding ID: {{err}}", err)
	}

	var (
		pub  [32]byte
		priv [32]byte
	)
	copy(priv[:], bytes)
	curve25519.ScalarBaseMult(&pub, &priv)
	privb64StdStr := base64.StdEncoding.EncodeToString(priv[:])
	pubb64StdStr := base64.StdEncoding.EncodeToString(pub[:])

	d.Set("private", privb64StdStr)
	d.Set("public", pubb64StdStr)

	return nil
}

func ImportPeer(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()

	_, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return nil, errwrap.Wrapf("Error decoding ID: {{err}}", err)
	}

	d.SetId(id)

	return []*schema.ResourceData{d}, nil
}
