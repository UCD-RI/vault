package command

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*AgentPingCommand)(nil)
var _ cli.CommandAutocomplete = (*AgentCommand)(nil)

type AgentPingCommand struct {
	*BaseCommand
}

func (c *AgentPingCommand) Client() (*api.Client, error) {
	client, err := c.BaseCommand.Client()
	if err != nil {
		return nil, err
	}
	return api.NewAgentClient(client)
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

	secret, err := client.Logical().Read("auth/approle/role/approle")
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error reading auth/approle/role/approle: %v", err))
		return 2
	}

	if c.flagField != "" {
		return PrintRawField(c.UI, secret, c.flagField)
	}

	return OutputSecret(c.UI, secret)
}
