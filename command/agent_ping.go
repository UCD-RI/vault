package command

import (
	"fmt"
	"strings"

	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*AgentPingCommand)(nil)
var _ cli.CommandAutocomplete = (*AgentCommand)(nil)

type AgentPingCommand struct {
	*BaseCommand
}

func (c *AgentPingCommand) Synopsis() string {
	return "Talks to Vault agent"
}

func (c *AgentPingCommand) Help() string {
	helpText := `
Usage: vault agent ping
` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *AgentPingCommand) Flags() *FlagSets {
	return c.flagSet(FlagSetHTTP | FlagSetOutputField | FlagSetOutputFormat)
}

func (c *AgentPingCommand) AutocompleteArgs() complete.Predictor {
	return c.PredictVaultFiles()
}

func (c *AgentPingCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *AgentPingCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	secret, err := client.Logical().Read("auth/approle/role/approle/role-id")
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error reading role id: %v", err))
		return 2
	}
	roleID := secret.Data["role_id"].(string)

	secret, err = client.Logical().Write("auth/approle/role/approle/secret-id", nil)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error reading secret id: %v", err))
		return 2
	}
	secretID := secret.Data["secret_id"].(string)

	secret, err = client.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error performing approle login: %v", err))
		return 2
	}

	return OutputSecret(c.UI, secret)
}
