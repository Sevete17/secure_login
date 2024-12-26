package main

import (
	"errors"
	"fmt"
	"net/http"
)

var ErrUnauthorized = errors.New("Unauthorized")

func Authorize(r *http.Request) error {
	username := r.FormValue("username")
	user, ok := users[username]
	if !ok {
		return ErrUnauthorized // User not found
	}

	// Get the Session Token from the Cookie
	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" || st.Value != user.SessionToken {
		return ErrUnauthorized
	}

	// Get the CSRF token from the headers
	csrf := r.Header.Get("X-CSRF-Token")
	if csrf != user.CSRFToken || csrf == "" {
		fmt.Printf("CSRF token mismatch: expected %s, got %s\n", user.CSRFToken, csrf)
		return ErrUnauthorized
	}

	return nil
}
