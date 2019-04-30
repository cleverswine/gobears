package main

import (
	"fmt"
	"net/http"
	"time"
	"github.com/cleverswine/gobears"
)

func main() {
	// specify an OAuth2 endpoint, required scopes (if any), and a signing key cache timeout
	auth := gobears.New("https://login.microsoftonline.com/common/v2.0", []string { }, time.Hour * 24)
	// a valid bearer token from login.microsoftonline.com is now required to access "/"
	http.HandleFunc("/", auth.WithBearerToken(hello))
	http.ListenAndServe(":80", nil)
}

func hello(w http.ResponseWriter, r *http.Request){
	claims := r.Context().Value(gobears.ClaimsType(gobears.ClaimsKey)).(*gobears.Claims)
	fmt.Fprintf(w, "Hello World! I am secure. Subject from token: " + claims.Subject)
}