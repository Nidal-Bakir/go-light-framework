package otp

import (
	"crypto/sha3"
	"fmt"
)

// Hashes the OTP using SHA3-256 and encodes the result as a hexadecimal string.
// Do not modify this function without proper preparation, as it will break
// OTP compatibility with currently deployed systems.
func HashOtp(otp string) string {
	return fmt.Sprintf("%x", sha3.Sum256([]byte(otp)))
}
