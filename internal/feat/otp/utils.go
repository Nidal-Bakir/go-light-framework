package otp

import (
	"crypto/sha256"
	"fmt"
)

// Hashes the OTP using SHA-256 and encodes the result as a hexadecimal string.
// Do not modify this function without proper preparation, as it will break
// OTP compatibility with currently deployed systems.
func HashOtp(otp string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(otp)))
}
