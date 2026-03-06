// pkg/analysis/expression/wildcard.go
package expression

import (
	"fmt"
	"strings"
)

// Wildcard represents a user-controllable value that matches anything
type Wildcard struct {
	name string
}

// NewWildcard creates a new Wildcard value
func NewWildcard(name string) *Wildcard {
	return &Wildcard{name: name}
}

// Equals checks equality - Wildcard matches any non-context value, or same context
func (w *Wildcard) Equals(other Value) bool {
	// If comparing with another Wildcard, check if same context
	if otherW, ok := other.(*Wildcard); ok {
		return w.name == otherW.name
	}

	// Wildcard matches anything user-controllable (not another github context)
	return true
}

// String returns string representation
func (w *Wildcard) String() string {
	return fmt.Sprintf("Wildcard(%s)", w.name)
}

// IsTruthy returns true (wildcards are truthy)
func (w *Wildcard) IsTruthy() bool {
	return true
}

// FlexibleAction represents an event action that can have multiple values
type FlexibleAction struct {
	options []string
}

// NewFlexibleAction creates a new FlexibleAction value
func NewFlexibleAction(options []string) *FlexibleAction {
	return &FlexibleAction{options: options}
}

// Equals checks if the other value matches any of the flexible options
func (f *FlexibleAction) Equals(other Value) bool {
	if s, ok := other.(*StringValue); ok {
		for _, opt := range f.options {
			if opt == s.value {
				return true
			}
		}
	}
	return false
}

// String returns string representation
func (f *FlexibleAction) String() string {
	return fmt.Sprintf("FlexibleAction(%v)", f.options)
}

// IsTruthy returns true (flexible actions are truthy)
func (f *FlexibleAction) IsTruthy() bool {
	return true
}

// StringValue represents a string value
type StringValue struct {
	value string
}

// NewStringValue creates a new StringValue
func NewStringValue(value string) *StringValue {
	return &StringValue{value: value}
}

// Equals checks string equality
func (s *StringValue) Equals(other Value) bool {
	// If other is Wildcard, delegate to Wildcard's Equals
	if w, ok := other.(*Wildcard); ok {
		return w.Equals(s)
	}

	// If other is FlexibleAction, delegate to FlexibleAction's Equals
	if f, ok := other.(*FlexibleAction); ok {
		return f.Equals(s)
	}

	// String comparison
	if otherS, ok := other.(*StringValue); ok {
		return s.value == otherS.value
	}

	return false
}

// String returns string representation
func (s *StringValue) String() string {
	return s.value
}

// IsTruthy returns true for non-empty strings
func (s *StringValue) IsTruthy() bool {
	return len(strings.TrimSpace(s.value)) > 0
}

// BoolValue represents a boolean value
type BoolValue struct {
	value bool
}

// NewBoolValue creates a new BoolValue
func NewBoolValue(value bool) *BoolValue {
	return &BoolValue{value: value}
}

// Equals checks boolean equality
func (b *BoolValue) Equals(other Value) bool {
	if otherB, ok := other.(*BoolValue); ok {
		return b.value == otherB.value
	}
	return false
}

// String returns string representation
func (b *BoolValue) String() string {
	if b.value {
		return "true"
	}
	return "false"
}

// IsTruthy returns the boolean value
func (b *BoolValue) IsTruthy() bool {
	return b.value
}
