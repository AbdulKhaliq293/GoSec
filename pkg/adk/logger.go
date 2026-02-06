package adk

import "fmt"

var DebugEnabled bool

// Debugf prints messages only if DebugEnabled is true
func Debugf(format string, args ...interface{}) {
	if DebugEnabled {
		fmt.Printf("[DEBUG] "+format+"\n", args...)
	}
}

// Infof prints messages always (standard output)
func Infof(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}
