package utils

import (
	"os"
	"time"
)

// IsExpired determines if the given expiresAt time has expired relative to the given time 'now',
// taking into account the given expirationBuffer.  If the buffer is zero or negative, the function
// returns true if expiresAt is before now.  If the buffer is positive, the function returns true if
// now is after expiresAt minus the buffer.
func IsExpired(expiresAt time.Time, now time.Time, expirationBuffer time.Duration) bool {
	return now.After(expiresAt.Add(-expirationBuffer))
}

// FileIsExists checks if a file exists.
//
// The function returns false if the file does not exist or if there was an error
// while checking.
func FileIsExists(filename string) bool {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	} else if err != nil {
		return false
	}
	return true
}
