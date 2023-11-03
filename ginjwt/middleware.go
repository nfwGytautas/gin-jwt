package ginjwt

import (
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Get token info from gin context
func GetTokenInfo(c *gin.Context) (TokenInfo, error) {
	tokenInfo, exists := c.Get("TokenInfo")
	if !exists {
		// Error
		return TokenInfo{}, errors.New("token info not set, make sure authentication middleware is used")
	}

	return tokenInfo.(TokenInfo), nil
}

/*
Middleware for authenticating

Usage:
r.Use(ginjwt.AuthenticationMiddleware())
*/
func AuthenticationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		_, err := parseTokenOrFail(c)
		if err != nil {
			return
		}

		c.Next()
	}
}

/*
Middleware for authorization

Usage:
r.Use(ginjwt.AuthorizationMiddleware([]string{"role"}))
*/
func AuthorizationMiddleware(roles []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		info, err := parseTokenOrFail(c)
		if err != nil {
			return
		}

		if !isElementInArray(roles, info.Role) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"Info": "Access denied, check with your IT department",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Parse token or abort request
func parseTokenOrFail(c *gin.Context) (TokenInfo, error) {
	tokenString := c.Query("token")

	if tokenString == "" {
		// Token empty check if it is inside Authorization header
		tokenString = c.Request.Header.Get("Authorization")

		// Since this is bearer token we need to parse the token out
		if len(strings.Split(tokenString, " ")) == 2 {
			tokenString = strings.Split(tokenString, " ")[1]
		} else {
			c.JSON(http.StatusBadRequest, gin.H{
				"Info": "Authorization token not specified",
			})
			c.Abort()
			return TokenInfo{}, errors.New("token not specified")
		}
	}

	info, err := ParseToken(tokenString)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"Info": "Failed to parse authorization token",
		})
		c.Abort()
		return TokenInfo{}, err
	}

	if !info.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{
			"Info": "Access denied, token invalid",
		})
		c.Abort()
		return TokenInfo{}, errors.New("token invalid")
	}

	c.Set("TokenInfo", info)
	return info, nil
}
