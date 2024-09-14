package disconcierge

import (
	"reflect"
	"strings"
	"testing"
)

func TestRuntimeConfigUpdateKeys(t *testing.T) {
	// Get JSON field names for RuntimeConfig and nested types
	runtimeConfigType := reflect.TypeOf(RuntimeConfig{})
	runtimeConfigFields := make(map[string]bool)
	for i := 0; i < runtimeConfigType.NumField(); i++ {
		field := runtimeConfigType.Field(i)
		jsonTag := field.Tag.Get("json")
		if jsonTag != "" && jsonTag != "-" {
			runtimeConfigFields[jsonTag] = true
		}
	}

	commandOptionType := reflect.TypeOf(CommandOptions{})
	for i := 0; i < commandOptionType.NumField(); i++ {
		field := commandOptionType.Field(i)
		jsonTag := field.Tag.Get("json")
		if jsonTag != "" && jsonTag != "-" {
			runtimeConfigFields[jsonTag] = true
		}
	}

	runSettingsType := reflect.TypeOf(OpenAIRunSettings{})
	for i := 0; i < runSettingsType.NumField(); i++ {
		field := runSettingsType.Field(i)
		jsonTag := field.Tag.Get("json")
		if jsonTag != "" && jsonTag != "-" {
			runtimeConfigFields[jsonTag] = true
		}
	}

	// Get JSON field names for RuntimeConfigUpdate
	updateType := reflect.TypeOf(RuntimeConfigUpdate{})
	for i := 0; i < updateType.NumField(); i++ {
		field := updateType.Field(i)
		jsonTag := field.Tag.Get("json")
		if jsonTag != "" && jsonTag != "-" {
			jsonTag, _, _ = strings.Cut(field.Tag.Get("json"), ",")
			if !runtimeConfigFields[jsonTag] {
				t.Errorf(
					"Field %s in RuntimeConfigUpdate is not present in RuntimeConfig",
					jsonTag,
				)
			}
		}
	}
}
