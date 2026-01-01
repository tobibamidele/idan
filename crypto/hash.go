package crypto

import (
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

func getSHA256Hash(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}

// HashPassword hashes a password using bcrypt with the specified cost
func HashPassword(password string, cost int) (string, error) {
	// Get SHA256 first because bcrypt errors out on passwords longer than 72 chars
	password = getSHA256Hash(password)
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

// CheckPassword compares plain text password with a hashed password
func CheckPassword(password, hash string) bool {
	password = getSHA256Hash(password)
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// NeedsCostUpdate checks if a password hash needs to be updated due to cost change
func NeedsCostUpdate(hash string, desiredCost int) (bool, error) {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return false, err
	}
	return cost != desiredCost, nil
}
