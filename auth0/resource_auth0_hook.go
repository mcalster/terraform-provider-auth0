package auth0

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"net/http"
	"regexp"

	"gopkg.in/auth0.v4"
	"gopkg.in/auth0.v4/management"
)

func newHook() *schema.Resource {
	return &schema.Resource{

		Create: createHook,
		Read:   readHook,
		Update: updateHook,
		Delete: deleteHook,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validateHookNameFunc(),
				Description:  "Name of this hook",
			},
			"script": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Code to be executed when this hook runs",
			},
			"trigger_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				ValidateFunc: validation.StringInSlice([]string{
					"credentials-exchange",
					"pre-user-registration",
					"post-user-registration",
					"post-change-password",
				}, false),
				Description: "Execution stage of this rule. Can be " +
					"credentials-exchange, pre-user-registration, " +
					"post-user-registration, post-change-password" +
					", or send-phone-message",
			},
			"secrets": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "The secrets associated with the hook",
				Elem:        schema.TypeString,
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Whether the hook is enabled, or disabled",
			},
		},
	}
}

func createHook(d *schema.ResourceData, m interface{}) error {
	c := buildHook(d)
	api := m.(*management.Management)
	if err := api.Hook.Create(c); err != nil {
		return err
	}
	d.SetId(auth0.StringValue(c.ID))
	if err := upsertHookSecrets(d, m); err != nil {
		return err
	}
	return readHook(d, m)
}

func readHook(d *schema.ResourceData, m interface{}) error {
	api := m.(*management.Management)
	c, err := api.Hook.Read(d.Id())
	if err != nil {
		if mErr, ok := err.(management.Error); ok {
			if mErr.Status() == http.StatusNotFound {
				d.SetId("")
				return nil
			}
		}
		return err
	}

	d.Set("name", c.Name)
	d.Set("script", c.Script)
	d.Set("trigger_id", c.TriggerID)
	d.Set("enabled", c.Enabled)
	return nil
}

func updateHook(d *schema.ResourceData, m interface{}) error {
	c := buildHook(d)
	api := m.(*management.Management)
	err := api.Hook.Update(d.Id(), c)
	if err != nil {
		return err
	}
	if err = upsertHookSecrets(d, m); err != nil {
		return err
	}
	return readHook(d, m)
}

func upsertHookSecrets(d *schema.ResourceData, m interface{}) error {
	if d.IsNewResource() || d.HasChange("secrets") {
		secrets := Map(d, "secrets")
		api := m.(*management.Management)
		var secretsToAdd map[string]interface{}
		if secretsBefore, err := api.Hook.Secrets(d.Id()); err == nil && secretsBefore != nil {
			var keysToRemove []string
			secretsToAdd = map[string]interface{}{}
			secretsToUpdate := map[string]interface{}{}
			keysBefore := secretsBefore.Keys()
			keysNow := make([]string, len(secrets))
			if len(secrets) > 0 {
				i := 0
				for k := range secrets {
					keysNow[i] = k
					keyFound := false
					for _, beforeKey := range keysBefore {
						if beforeKey == k {
							keyFound = true
							break
						}
					}
					if keyFound {
						secretsToUpdate[k] = secrets[k]
					} else {
						secretsToAdd[k] = secrets[k]
					}
					i++
				}
			}
			for _, beforeKey := range keysBefore {
				keyFound := false
				for _, nowKey := range keysNow {
					if beforeKey == nowKey {
						keyFound = true
						break
					}
				}
				if !keyFound {
					keysToRemove = append(keysToRemove, beforeKey)
				}
			}
			if len(keysToRemove) > 0 {
				if err := api.Hook.RemoveSecrets(d.Id(), keysToRemove...); err != nil {
					return err
				}
			}
			if len(secretsToUpdate) > 0 {
				if err := api.Hook.UpdateSecrets(d.Id(), toHookSecrets(secretsToUpdate)); err != nil {
					return err
				}
			}
		} else {
			secretsToAdd = secrets
		}

		if len(secretsToAdd) > 0 {
			return api.Hook.CreateSecrets(d.Id(), toHookSecrets(secretsToAdd))
		}
	}
	return nil
}

func toHookSecrets(val map[string]interface{}) *management.HookSecrets {
	hookSecrets := management.HookSecrets{}
	for key, value := range val {
		if strVal, ok := value.(string); ok {
			hookSecrets[key] = strVal
		}
	}
	return &hookSecrets
}

func deleteHook(d *schema.ResourceData, m interface{}) error {
	api := m.(*management.Management)
	err := api.Hook.Delete(d.Id())
	if err != nil {
		if mErr, ok := err.(management.Error); ok {
			if mErr.Status() == http.StatusNotFound {
				d.SetId("")
				return nil
			}
		}
		return err
	}
	return err
}

func buildHook(d *schema.ResourceData) *management.Hook {
	return &management.Hook{
		Name:      String(d, "name"),
		Script:    String(d, "script"),
		TriggerID: String(d, "trigger_id", IsNewResource()),
		Enabled:   Bool(d, "enabled"),
	}
}

func validateHookNameFunc() schema.SchemaValidateFunc {
	return validation.StringMatch(
		regexp.MustCompile("^[^\\s-][\\w -]+[^\\s-]$"),
		"Can only contain alphanumeric characters, spaces and '-'. Can neither start nor end with '-' or spaces.")
}
