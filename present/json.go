package present

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func JSON(jms *json.RawMessage) error {
	var out bytes.Buffer

	if err := json.Indent(&out, *jms, "", "  "); err != nil {
		return fmt.Errorf("error indenting JSON: %w", err)
	}

	fmt.Println(out.String())

	return nil
}
