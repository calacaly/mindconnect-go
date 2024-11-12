package utils

import (
	"time"
)

// IsExpired determines if a given expiresAt time has expired when considering
// the current time and an additional expiration buffer.
//
// The expiration buffer is a duration subtracted from the expiresAt time
// to determine the effective expiration time. This is useful for avoiding
// expiration race conditions due to clock skew.
//
// Returns true if the expiresAt time has expired, false otherwise.
func IsExpired(expiresAt time.Time, now time.Time, expirationBuffer time.Duration) bool {
	return now.After(expiresAt.Add(-expirationBuffer))
}
