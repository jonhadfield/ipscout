package policy

import (
	"fmt"
	"strings"
)

func Confirm(item, request string) bool {
	fmt.Println(item)
	fmt.Printf("%s [y|N]: ", request)

	var s string

	if _, err := fmt.Scanln(&s); err != nil {
		return false
	}

	s = strings.TrimSpace(s)

	s = strings.ToLower(s)

	if s == "y" || s == "yes" {
		return true
	}

	return false
}
