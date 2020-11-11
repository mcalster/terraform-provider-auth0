package auth0

import (
	"log"
	"strings"
	"testing"

	"github.com/alexkappa/terraform-provider-auth0/auth0/internal/random"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
)

func init() {
	resource.AddTestSweepers("auth0_log_stream", &resource.Sweeper{
		Name: "auth0_log_stream",
		F: func(_ string) error {
			api, err := Auth0()
			if err != nil {
				return err
			}
			l, err := api.LogStream.List()
			if err != nil {
				return err
			}
			for _, logstream := range l {
				if strings.Contains(logstream.GetName(), "Test") {
					log.Printf("[DEBUG] Deleting logstream %v\n", logstream.GetName())
					if e := api.LogStream.Delete(logstream.GetID()); e != nil {
						multierror.Append(err, e)
					}
				}
			}
			if err != nil {
				return err
			}
			return nil
		},
	})
}

func TestAccLogStreamHttp(t *testing.T) {
	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		Providers: map[string]terraform.ResourceProvider{
			"auth0": Provider(),
		},
		Steps: []resource.TestStep{
			{
				Config: random.Template(logStreamHTTPConfig, rand),
				Check: resource.ComposeTestCheckFunc(
					random.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "name", "Acceptance-Test-LogStream-http-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "type", "http"),
					//resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "status", "active"),
					resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "http_endpoint", "https://example.com/webhook/logs"),
					resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "http_content_type", "application/json"),
					resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "http_content_format", "JSONLINES"),
					resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "http_authorization", "AKIAXXXXXXXXXXXXXXXX"),
				),
			},
		},
	})
}

const logStreamHTTPConfig = `
resource "auth0_log_stream" "my_log_stream" {
	name = "Acceptance-Test-LogStream-http-{{.random}}"
	type = "http"
	http_endpoint = "https://example.com/webhook/logs"
	http_content_type = "application/json"
	http_content_format = "JSONLINES"
	http_authorization = "AKIAXXXXXXXXXXXXXXXX"
}
`

func TestAccLogStreamEventBridge(t *testing.T) {
	rand := random.String(6)
	resource.Test(t, resource.TestCase{
		Providers: map[string]terraform.ResourceProvider{
			"auth0": Provider(),
		},
		Steps: []resource.TestStep{
			{
				Config: random.Template(logStreamAwsEventBridgeConfig, rand),
				Check: resource.ComposeTestCheckFunc(
					random.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "name", "Acceptance-Test-LogStream-aws-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "type", "eventbridge"),
					resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "aws_account_id", "999999999999"),
					resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "aws_region", "us-west-2"),
				),
			},
		},
	})
}

const logStreamAwsEventBridgeConfig = `
resource "auth0_log_stream" "my_log_stream" {
	name = "Acceptance-Test-LogStream-aws-{{.random}}"
	type = "eventbridge"
	aws_account_id = "999999999999"
	aws_region = "us-west-2"
}
`

//This test fails it subscription key is not valid, or Eventgrid Resource Provider is not registered in the subscription
func TestAccLogStreamEventGrid(t *testing.T) {
	rand := random.String(6)

	t.Skip("this test requires an active subscription")

	resource.Test(t, resource.TestCase{
		Providers: map[string]terraform.ResourceProvider{
			"auth0": Provider(),
		},
		Steps: []resource.TestStep{
			{
				Config: random.Template(logStreamAzureEventGridConfig, rand),
				Check: resource.ComposeTestCheckFunc(
					random.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "name", "Acceptance-Test-LogStream-azure-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "type", "eventgrid"),
					resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "azure_subscription_id", "b69a6835-57c7-4d53-b0d5-1c6ae580b6d5"),
					resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "azure_region", "northeurope"),
					resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "azure_resource_group", "azure-logs-rg"),
				),
			},
		},
	})
}

const logStreamAzureEventGridConfig = `
resource "auth0_log_stream" "my_log_stream-{{.random}}" {
	name = "Acceptance-Test-LogStream-azure"
	type = "eventgrid"
	azure_subscription_id = "b69a6835-57c7-4d53-b0d5-1c6ae580b6d5"
	azure_region = "northeurope"
	azure_resource_group = "azure-logs-rg"
}
`

func TestAccLogStreamDatadog(t *testing.T) {
	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		Providers: map[string]terraform.ResourceProvider{
			"auth0": Provider(),
		},
		Steps: []resource.TestStep{
			{
				Config: random.Template(logStreamDatadogConfig, rand),
				Check: resource.ComposeTestCheckFunc(
					random.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "name", "Acceptance-Test-LogStream-datadog-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "type", "datadog"),
					resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "datadog_region", "us"),
					resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "datadog_api_key", "121233123455"),
				),
			},
		},
	})
}

const logStreamDatadogConfig = `
resource "auth0_log_stream" "my_log_stream" {
	name = "Acceptance-Test-LogStream-datadog-{{.random}}"
	type = "datadog"
	datadog_region = "us"
	datadog_api_key = "121233123455"
}
`

func TestAccLogStreamSplunk(t *testing.T) {
	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		Providers: map[string]terraform.ResourceProvider{
			"auth0": Provider(),
		},
		Steps: []resource.TestStep{
			{
				Config: random.Template(logStreamSplunkConfig, rand),
				Check: resource.ComposeTestCheckFunc(
					random.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "name", "Acceptance-Test-LogStream-splunk-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "type", "splunk"),
					resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "splunk_domain", "demo.splunk.com"),
					resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "splunk_token", "12a34ab5-c6d7-8901-23ef-456b7c89d0c1"),
					resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "splunk_port", "8088"),
					resource.TestCheckResourceAttr("auth0_log_stream.my_log_stream", "splunk_secure", "true"),
				),
			},
		},
	})
}

const logStreamSplunkConfig = `
resource "auth0_log_stream" "my_log_stream" {
	name = "Acceptance-Test-LogStream-splunk-{{.random}}"
	type = "splunk"
	splunk_domain = "demo.splunk.com"
	splunk_token = "12a34ab5-c6d7-8901-23ef-456b7c89d0c1"
	splunk_port = "8088"
	splunk_secure = "true"
}
`
