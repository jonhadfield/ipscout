package present

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// CSV outputs provider results as CSV to stdout.
func CSV(jm *json.RawMessage) error {
	var data map[string]json.RawMessage
	if err := json.Unmarshal(*jm, &data); err != nil {
		return fmt.Errorf("error unmarshalling JSON for CSV: %w", err)
	}

	w := csv.NewWriter(os.Stdout)
	defer w.Flush()

	if err := w.Write([]string{"provider", "key", "value"}); err != nil {
		return fmt.Errorf("error writing CSV header: %w", err)
	}

	// sort provider names for deterministic output
	providerNames := make([]string, 0, len(data))
	for name := range data {
		providerNames = append(providerNames, name)
	}

	sort.Strings(providerNames)

	for _, name := range providerNames {
		raw := data[name]

		var fields map[string]any
		if err := json.Unmarshal(raw, &fields); err != nil {
			// provider data is not a flat object; output as single value
			if wErr := w.Write([]string{name, "data", string(raw)}); wErr != nil {
				return fmt.Errorf("error writing CSV row: %w", wErr)
			}

			continue
		}

		keys := make([]string, 0, len(fields))
		for k := range fields {
			keys = append(keys, k)
		}

		sort.Strings(keys)

		for _, k := range keys {
			if wErr := w.Write([]string{name, k, fmt.Sprintf("%v", fields[k])}); wErr != nil {
				return fmt.Errorf("error writing CSV row: %w", wErr)
			}
		}
	}

	return nil
}
