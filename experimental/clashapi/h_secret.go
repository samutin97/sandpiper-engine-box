package clashapi

import "crypto/subtle"

// secretMatches compares a token with the server secret in constant time. //H
func secretMatches(token, serverSecret string) bool {
	return subtle.ConstantTimeCompare([]byte(token), []byte(serverSecret)) == 1
}
