package ginjwt

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Struct for containing token info
type TokenInfo struct {
	Valid bool
	ID    uint
	Role  string
}

// API Secret for parsing JWT tokens
var gSecret string

// Setup token lib
func Setup(secret string) error {
	if len(secret) == 0 {
		return errors.New("empty api secret key")
	}

	gSecret = secret

	return nil
}

// Parse a token from from string
func ParseToken(tokenString string) (TokenInfo, error) {
	result := TokenInfo{}
	result.Valid = false

	jwtToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)

		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(gSecret), nil
	})

	if err != nil {
		return result, err
	}

	// Token valid fill token information
	claims, ok := jwtToken.Claims.(jwt.MapClaims)

	if !ok || !jwtToken.Valid {
		return result, nil
	}

	// User id
	uid, err := strconv.ParseUint(fmt.Sprintf("%.0f", claims["user_id"]), 10, 32)
	if err != nil {
		return result, nil
	}

	result.ID = uint(uid)

	// Role
	result.Role = claims["role"].(string)

	result.Valid = true
	return result, nil
}

// Generates a JWT token
func GenerateToken(id uint, role string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS512)
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = id
	claims["role"] = role
	claims["expiration"] = time.Now().Add(10 * time.Minute)

	tokenString, err := token.SignedString([]byte(gSecret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
