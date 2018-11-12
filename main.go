package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/coreos/go-oidc"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

func main() {

	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		log.Fatal(errors.Wrap(err, "error creating oidc provider"))
	}

	clientID := "224600073722-o248pf5sr04qkpr3dnloismhub2mae0q.apps.googleusercontent.com"
	clientSecret := ""

	redirectURL := "http://localhost:9999/code"

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "email"},
	}

	var rawState [40]byte

	_, err = rand.Read(rawState[:])

	if err != nil {
		log.Fatal(errors.Wrap(err, "error generating oauth state"))
	}

	state := hex.EncodeToString(rawState[:])

	url := oauth2Config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("hd", "theplant.jp"),
		//oauth2.SetAuthURLParam("prompt", "consent")
	)
	cmd := exec.Command("open", url)
	if err := cmd.Run(); err != nil {
		log.Fatal(errors.Wrap(err, "error opening page in browser"))
	}

	server := http.Server{
		Addr: ":9999",
	}
	server.SetKeepAlivesEnabled(false)

	requestSignal := make(chan error)
	serverSignal := make(chan bool)

	server.Handler = handleOAuth2Callback(provider, oauth2Config, state, requestSignal)

	go func() {
		err := <-requestSignal

		err2 := server.Shutdown(ctx)

		if err2 != nil {
			log.Fatal(errors.Wrap(err2, "error on server shutdown"))
		}

		if err != nil {
			log.Fatal(err)
		}

		serverSignal <- true
	}()

	err = server.ListenAndServe()

	if err != nil && err != http.ErrServerClosed {
		log.Fatal(errors.Wrap(err, "error from server.ListenAndServe"))
	}

	<-serverSignal
}

func writeError(w http.ResponseWriter, err error, msg string) error {
	if err == nil {
		err = errors.New(msg)
	} else {
		err = errors.Wrap(err, msg)
	}

	w.WriteHeader(500)
	writeString(w, fmt.Sprintf("%v", err))

	return err
}

func handleOAuth2Callback(provider *oidc.Provider, oauth2Config oauth2.Config, state string, signal chan error) http.HandlerFunc {

	verifier := provider.Verifier(&oidc.Config{ClientID: oauth2Config.ClientID})

	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		// Quit after processing a single request
		defer func() {
			signal <- err
		}()

		// Verify request state matches response state
		reqState := r.URL.Query().Get("state")
		if reqState != state {
			err = writeError(w, nil, "response state does not match request state")
			return
		}

		// Exchange authorisation code for access/id token
		oauth2Token, err := oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			err = writeError(w, err, "error exchanging authorisation code for access/id tokens")
			return
		}

		// Extract ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			err = writeError(w, nil, "no id_token included when fetching access token")
			return
		}

		// Parse and verify ID Token payload.
		idToken, err := verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			err = writeError(w, err, "error verifying id token")
			return
		}

		// Extract custom claim
		var claims struct {
			Email   string `json:"email"`
			Subject string `json:"sub"`
		}
		err = idToken.Claims(&claims)
		if err != nil {
			err = writeError(w, err, "error extracting claims from id token")
			return
		}

		arn := ""
		if len(os.Args) > 1 {
			arn = os.Args[1]
		}

		if arn == "" {
			writeString(w, fmt.Sprintf("no role ARN provided<br>claims: %+v", claims))
			err = errors.New("error: no arn provided")
			return
		}

		input := sts.AssumeRoleWithWebIdentityInput{
			RoleArn:          &arn,
			RoleSessionName:  &claims.Email,
			WebIdentityToken: &rawIDToken,
		}

		type Result struct {
			Version int
			sts.Credentials
		}

		sess, err := session.NewSession()
		if err != nil {
			err = writeError(w, err, "error creating aws session")
			return
		}

		svc := sts.New(sess)
		output, err := svc.AssumeRoleWithWebIdentity(&input)
		if err != nil {
			err = writeError(w, err, fmt.Sprintf("error assuming role %q with web identity", arn))
			return
		}

		result := Result{
			Version:     1,
			Credentials: *output.Credentials,
		}
		b, err := json.Marshal(result)
		if err != nil {
			err = writeError(w, err, "error serialising credentials to json")
			return
		}

		// Write credentials to stdout
		os.Stdout.Write(b)

		// Close the browser window
		writeString(w, "<script>window.close()</script>")
	}
}

func writeString(w http.ResponseWriter, s string) {
	// <link> is to prevent browsers trying to load a favicon for this page
	w.Write([]byte(`<!DOCTYPE html><html><link rel="icon" href="data:;base64,iVBORw0KGgo="><body>` + s))

}
