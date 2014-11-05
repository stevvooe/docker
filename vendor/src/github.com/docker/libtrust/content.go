package libtrust

import (
	"encoding/json"
	"errors"
	"fmt"
)

var (
	// ErrUnknownSignContent is used when attempting to perform an
	// action on a signature but the content is not able to be
	// understood.
	ErrUnknownSignContent = errors.New("unknown sign content")
)

// ExtractSubject extracts the subject intended action on
// that subject from the payload.  If the payload content
// cannot be understood, ErrUnknownSignContent is returned.
func (js *JSONSignature) ExtractSubject() (string, string, error) {
	// Parse content
	content, err := js.Payload()
	if err != nil {
		return "", "", err
	}
	var data map[string]interface{}
	if err := json.Unmarshal(content, &data); err != nil {
		return "", "", err
	}

	version, ok := data["schemaVersion"]
	if !ok {
		return "", "", ErrUnknownSignContent
	}

	if version == float64(1) {
		name, ok := data["name"]
		if !ok {
			return "", "", errors.New("invalid version 1 build content")
		}
		return fmt.Sprintf("/docker/%s", name), "build", nil

	}
	return "", "", ErrUnknownSignContent
}
