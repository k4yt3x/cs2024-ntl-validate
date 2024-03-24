package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/gin-gonic/gin"
)

type TokenRequest struct {
	Token string `json:"token"`
}

// validateToken validates the token by executing the validate binary
func validateToken(validateBinaryPath string, token string) (bool, error) {
	err := exec.Command(validateBinaryPath, token).Run()
	if err != nil {
		_, isExitError := err.(*exec.ExitError)
		if isExitError {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func main() {
	// parse command line arguments
	if len(os.Args) < 2 {
		fmt.Println("usage: ./verifier [VALIDATE_BINARY_PATH]")
		os.Exit(1)
	}
	validateBinaryPath := os.Args[1]

	// create a new gin router
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// register route to validate token
	router.POST("/validate", func(context *gin.Context) {
		var tokenReq TokenRequest
		if err := context.ShouldBindJSON(&tokenReq); err != nil {
			context.JSON(400, gin.H{"error": "Invalid request"})
			return
		}
		isValid, err := validateToken(validateBinaryPath, tokenReq.Token)
		if err != nil {
			context.JSON(500, gin.H{"error": "Internal server error"})
			return
		}
		context.JSON(200, gin.H{"is_valid": isValid})
	})

	// start the server
	fmt.Println("Starting verifier service on port 8080...")
	if err := router.Run(":8080"); err != nil {
		fmt.Println("Error starting server:", err)
	}
}
