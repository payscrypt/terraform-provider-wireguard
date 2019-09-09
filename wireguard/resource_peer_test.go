package wireguard

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

type idLens struct {
	publicLen  int
	privateLen int
}

func TestAccResourcePeer(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccResourcePeerConfig,
				Check: resource.ComposeTestCheckFunc(
					testAccResourcePeerCheck("wireguard_peer.foo", &idLens{
						privateLen: 44,
						publicLen:  44,
					}),
				),
			},
		},
	})
}

func testAccResourcePeerCheck(id string, want *idLens) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[id]
		if !ok {
			return fmt.Errorf("Not found: %s", id)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("No ID is set")
		}

		publicStr := rs.Primary.Attributes["public"]
		privateStr := rs.Primary.Attributes["private"]

		if got, want := len(publicStr), want.publicLen; got != want {
			return fmt.Errorf("public string length is %d; want %d", got, want)
		}
		if got, want := len(privateStr), want.privateLen; got != want {
			return fmt.Errorf("private string length is %d; want %d", got, want)
		}

		return nil
	}
}

const (
	testAccResourcePeerConfig = `
resource "wireguard_peer" "foo" {
}
`
)
