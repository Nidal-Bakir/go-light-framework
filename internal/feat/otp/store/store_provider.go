package otp

import (
	"context"
	"time"
)

// StoreProvider defines operations for secure OTP storage and attempt tracking.
// Implementations must handle OTP lifecycle: creation, retrieval, verification,
// and automatic cleanup after expiration.
type StoreProvider interface {
	// StoreOtp stores a hashed OTP and returns a unique verification ID.
	// Creates a new entry with attempt counter initialized to 1.
	//
	// The caller must persist the returned ID (e.g., in user session or database)
	// for later verification. The OTP automatically expires after ExpiresAfter.
	//
	// Parameters:
	//   otpHash: Hashed/encrypted OTP value (never store plaintext OTPs)
	//   purpose: Context for OTP generation (login, password_reset, etc.)
	//   channel: Delivery method (email, sms, etc.)
	//   ExpiresAfter: Duration after which OTP becomes invalid
	//
	// Returns:
	//   id: Unique identifier for this OTP entry; required for all subsequent operations
	//   err: Storage error (nil if successful)
	StoreOtp(ctx context.Context, otpHash string, purpose otpPurpose, channel otpChannel, ExpiresAfter time.Duration) (id string, err error)

	// GetOtp retrieves the complete OTP entry for the given ID.
	// Returns nil if the entry doesn't exist or has expired.
	//
	// Use this method to inspect OTP metadata (purpose, channel, expiry)
	// without performing verification. For security, the returned model
	// should contain only the hashed OTP, not the plaintext value.
	GetOtp(ctx context.Context, id string) (*OtpStoreModel, error)

	// RemoveOtp deletes an OTP entry immediately.
	// Typically called after successful verification or when explicitly
	// invalidating an OTP (e.g., user requests new OTP).
	//
	// Removing a non-existent entry should not return an error.
	RemoveOtp(ctx context.Context, id string) error

	// IncrementAttemptCounter increments the attempt counter for an entry.
	// The counter starts at 1 when StoreOtp is called and increments up to
	// the specified limit. Once the limit is reached, no further increments occur.
	//
	// Non-existent entries return attempts=0 with limitReached=true (no error).
	//
	// Example (limit=2):
	//   1. StoreOtp() → attempts=1, limitReached=false
	//   2. IncrementAttemptCounter() → attempts=2, limitReached=false
	//   3. IncrementAttemptCounter() → attempts=2, limitReached=true
	//      (counter stops at limit, no further increments)
	//
	// Returns:
	//   attempts: Current attempt count (never exceeds limit)
	//   limitReached: True if attempt limit has been reached
	//   err: Error if operation fails (nil for non-existent entries)
	IncrementAttemptCounter(ctx context.Context, id string, limit int) (attempts int, limitReached bool, err error)
}

type otpChannel string
type otpPurpose string

const (
	EmailChannel otpChannel = "email"
	SMSChannel   otpChannel = "sms"

	AccountVerification otpPurpose = "account_verification"
	ResetPassword       otpPurpose = "reset_password"
)

func (c otpChannel) String() string {
	return string(c)
}
func (o otpPurpose) String() string {
	return string(o)
}

type OtpStoreModel struct {
	ID        string
	OtpHash   string
	Purpose   otpPurpose
	Channel   otpChannel
	Attempts  int
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt time.Time
}
