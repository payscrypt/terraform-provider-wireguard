package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/hcl2/hcl"
	"github.com/hashicorp/hcl2/hcl/hclsyntax"
	"github.com/hashicorp/terraform/helper/customdiff"
	"github.com/hashicorp/terraform/helper/schema"
	tflang "github.com/hashicorp/terraform/lang"
	"github.com/zclconf/go-cty/cty"
	ctyconvert "github.com/zclconf/go-cty/cty/convert"
	"golang.org/x/crypto/curve25519"
)

func resourcePeer() *schema.Resource {
	return &schema.Resource{
		Create: CreatePeer,
		Read:   ReadPeer,
		Update: UpdatePeer,
		Delete: schema.RemoveFromState,
		CustomizeDiff: customdiff.All(
			customdiff.ComputedIf("interface_rendered", func(d *schema.ResourceDiff, meta interface{}) bool {
				return d.HasChange("interface_template") || d.HasChange("vars")
			}),
			customdiff.ComputedIf("peer_rendered", func(d *schema.ResourceDiff, meta interface{}) bool {
				return d.HasChange("peer_template") || d.HasChange("vars")
			}),
		),

		Schema: map[string]*schema.Schema{
			"private_key": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"public_key": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"interface_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Contents of the template for interface config section",
			},
			"peer_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Contents of the template for peer config section",
			},
			"vars": {
				Type:         schema.TypeMap,
				Optional:     true,
				Default:      make(map[string]interface{}),
				Description:  "variables to substitute",
				ValidateFunc: validateVarsAttribute,
			},
			"interface_rendered": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "rendered interface section",
			},
			"peer_rendered": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "rendered peer section",
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

	return ReadPeer(d, meta)
}

func ReadPeer(d *schema.ResourceData, _ interface{}) error {
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
	d.Set("private_key", privb64StdStr)
	d.Set("public_key", pubb64StdStr)

	irendered, err := renderFile(d, "interface_template")
	if err != nil {
		return err
	}
	prendered, err := renderFile(d, "peer_template")
	if err != nil {
		return err
	}

	d.Set("interface_rendered", irendered)
	d.Set("peer_rendered", prendered)

	return nil
}

func UpdatePeer(d *schema.ResourceData, meta interface{}) error {
	return ReadPeer(d, meta)
}

type templateRenderError error

func renderFile(d *schema.ResourceData, field string) (string, error) {
	private := d.Get("private_key").(string)
	public := d.Get("public_key").(string)
	template := d.Get(field).(string)
	vars := d.Get("vars").(map[string]interface{})

	ctx := make(map[string]interface{})
	ctx["private_key"] = private
	ctx["public_key"] = public

	for k, v := range vars {
		ctx[k] = v
	}

	rendered, err := execute(template, ctx)
	if err != nil {
		return "", templateRenderError(
			fmt.Errorf("failed to render %s: %v", "interface_template", err),
		)
	}

	return rendered, nil
}

// execute parses and executes a template using vars.
func execute(s string, vars map[string]interface{}) (string, error) {
	expr, diags := hclsyntax.ParseTemplate([]byte(s), "<template_file>", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return "", diags
	}

	ctx := &hcl.EvalContext{
		Variables: map[string]cty.Value{},
	}
	for k, v := range vars {
		// In practice today this is always a string due to limitations of
		// the schema system. In future we'd like to support other types here.
		s, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("unexpected type for variable %q: %T", k, v)
		}
		ctx.Variables[k] = cty.StringVal(s)
	}

	// We borrow the functions from Terraform itself here. This is convenient
	// but note that this is coming from whatever version of Terraform we
	// have vendored in to this codebase, not from the version of Terraform
	// the user is running, and so the set of functions won't always match
	// between Terraform itself and this provider.
	// (Over time users will hopefully transition over to Terraform's built-in
	// templatefile function instead and we can phase this provider out.)
	scope := &tflang.Scope{
		BaseDir: ".",
	}
	ctx.Functions = scope.Functions()

	result, diags := expr.Value(ctx)
	if diags.HasErrors() {
		return "", diags
	}

	// Our result must always be a string, so we'll try to convert it.
	var err error
	result, err = ctyconvert.Convert(result, cty.String)
	if err != nil {
		return "", fmt.Errorf("invalid template result: %s", err)
	}

	return result.AsString(), nil
}

func validateVarsAttribute(v interface{}, key string) (ws []string, es []error) {
	// vars can only be primitives right now
	var badVars []string
	for k, v := range v.(map[string]interface{}) {
		switch v.(type) {
		case []interface{}:
			badVars = append(badVars, fmt.Sprintf("%s (list)", k))
		case map[string]interface{}:
			badVars = append(badVars, fmt.Sprintf("%s (map)", k))
		}
	}
	if len(badVars) > 0 {
		es = append(es, fmt.Errorf(
			"%s: cannot contain non-primitives; bad keys: %s",
			key, strings.Join(badVars, ", ")))
	}
	return
}
