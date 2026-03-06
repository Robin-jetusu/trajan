// Package attacks aggregates all Jenkins attack plugins via blank imports.
package attacks

import (
	_ "github.com/praetorian-inc/trajan/pkg/jenkins/attacks/credentialdump"
	_ "github.com/praetorian-inc/trajan/pkg/jenkins/attacks/jobinjection"
	_ "github.com/praetorian-inc/trajan/pkg/jenkins/attacks/scriptconsole"
)
