package wireguard

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/hashicorp/terraform/helper/customdiff"
	"github.com/hashicorp/terraform/helper/schema"
)

func resourceConfig() *schema.Resource {
	return &schema.Resource{
		Create: CreateConfig,
		Read:   ReadConfig,
		Update: UpdateConfig,
		Delete: schema.RemoveFromState,
		CustomizeDiff: customdiff.All(
			customdiff.ComputedIf("rendered", func(d *schema.ResourceDiff, meta interface{}) bool {
				return d.HasChange("interface") || d.HasChange("peer") || d.HasChange("all_peers")
			}),
		),

		Schema: map[string]*schema.Schema{
			"interface": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"peer": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"all_peers": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "all peers",
			},
			"rendered": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "rendered wireguard config",
			},
		},
	}
}

func CreateConfig(d *schema.ResourceData, meta interface{}) error {
	return ReadConfig(d, meta)
}

func ReadConfig(d *schema.ResourceData, _ interface{}) error {
	interfaceSection := d.Get("interface").(string)
	peerSection := d.Get("peer").(string)
	allPeers := d.Get("all_peers").([]interface{})

	rendered := interfaceSection + "\n\n"

	for _, p := range allPeers {
		t := p.(string)
		if peerSection != t {
			rendered = rendered + t + "\n\n"
		}
	}

	d.Set("rendered", rendered)
	d.SetId(hash(rendered))

	return nil
}

func UpdateConfig(d *schema.ResourceData, meta interface{}) error {
	return ReadConfig(d, meta)
}

func hash(s string) string {
	sha := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sha[:])
}
