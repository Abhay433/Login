package main

import (
	"net"
	"regexp"
	"strings"
)

// Validate email format using regex
func isValidEmailFormat(email string) bool {
	// Simple email regex
	regex := `^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(regex)
	return re.MatchString(email)
}

func hasMXRecords(email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	_, err := net.LookupMX(parts[1])
	return err == nil
}

// func main() {
// 	// Try different emails here
// 	email := "xyz@openai123.com"

// 	// First check: Format validation
// 	if !isValidEmailFormat(email) {
// 		fmt.Println("❌ Invalid email format")
// 		return
// 	}

// 	// Second check: MX records validation
// 	if hasMXRecords(email) {
// 		fmt.Println("✅ Valid email: Domain exists")
// 	} else {
// 		fmt.Println("❌ Domain does not exist")
// 	}
// }
