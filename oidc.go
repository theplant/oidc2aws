package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type idTokenResult struct {
	RawToken string
	Token    *oidc.IDToken
	Email    string
	Sub      string
}

func (this idTokenResult) Expiry() *time.Time {
	return &this.Token.Expiry
}

type idTokenMessage struct { // One of (either)...
	result idTokenResult // a result, or
	err    error         // an error
}

func openInBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux", "freebsd", "openbsd", "netbsd":
		cmd = exec.Command("xdg-open", url)
	default:
		return errors.New("unsupported platform for opening browser")
	}
	return errors.Wrap(cmd.Run(), "error opening page in browser")
}

func fetchIDToken(oc oidcConfig) (*idTokenResult, error) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, oc.Provider)
	if err != nil {
		return nil, errors.Wrap(err, "error creating oidc provider")
	}

	redirectURL := "http://localhost:9999/code"

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     oc.ClientID,
		ClientSecret: oc.ClientSecret,
		RedirectURL:  redirectURL,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "email"},
	}

	var rawState [40]byte

	_, err = rand.Read(rawState[:])

	if err != nil {
		return nil, errors.Wrap(err, "error generating oauth state")
	}

	state := hex.EncodeToString(rawState[:])

	url := oauth2Config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("hd", oc.HostedDomain),

		// If this is set, or if the user actually needs to
		// authenticate, we aren't able to automatically close the
		// browser window after authentication :(
		// oauth2.SetAuthURLParam("prompt", "consent")
	)

	if err := openInBrowser(url); err != nil {
		return nil, err
	}

	server := http.Server{
		Addr: ":9999",
	}
	server.SetKeepAlivesEnabled(false)

	requestSignal := make(chan idTokenMessage)
	serverSignal := make(chan idTokenMessage)

	server.Handler = handleOAuth2Callback(provider, oauth2Config, state, requestSignal)

	go func() {
		result := <-requestSignal

		err := server.Shutdown(ctx)

		if err != nil {
			result = idTokenMessage{
				err: errors.Wrap(err, "error on server shutdown"),
			}
		}

		serverSignal <- result
	}()

	err = server.ListenAndServe()

	if err != nil && err != http.ErrServerClosed {
		return nil, errors.Wrap(err, "error from server.ListenAndServe")
	}

	result := <-serverSignal

	if result.err != nil {
		return nil, err
	}

	return &result.result, nil
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

func handleOAuth2Callback(provider *oidc.Provider, oauth2Config oauth2.Config, state string, signal chan idTokenMessage) http.HandlerFunc {

	verifier := provider.Verifier(&oidc.Config{ClientID: oauth2Config.ClientID})

	return func(w http.ResponseWriter, r *http.Request) {
		// Verify request state matches response state
		reqState := r.URL.Query().Get("state")
		if reqState != state {
			signal <- idTokenMessage{err: writeError(w, nil, "response state does not match request state")}
			return
		}

		// Exchange authorisation code for access/id token
		oauth2Token, err := oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			signal <- idTokenMessage{err: writeError(w, err, "error exchanging authorisation code for access/id tokens")}
			return
		}

		// Extract ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			signal <- idTokenMessage{err: writeError(w, nil, "no id_token included when fetching access token")}
			return
		}

		// Parse and verify ID Token payload.
		idToken, err := verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			signal <- idTokenMessage{err: writeError(w, err, "error verifying id token")}
			return
		}

		// Extract custom claim
		var claims struct {
			Email   string `json:"email"`
			Subject string `json:"sub"`
		}
		err = idToken.Claims(&claims)
		if err != nil {
			signal <- idTokenMessage{err: writeError(w, err, "error extracting claims from id token")}
			return
		}

		// Pass result back
		signal <- idTokenMessage{
			result: idTokenResult{
				RawToken: rawIDToken,
				Token:    idToken,
				Email:    claims.Email,
				Sub:      claims.Subject,
			},
		}

		// Close the browser window
		writeString(w, "<script>window.close()</script>")
	}
}

func writeString(w http.ResponseWriter, s string) {
	// <link> is to prevent browsers trying to load a favicon for this page
	w.Write([]byte(`<!DOCTYPE html><html><link rel="icon" href="data:;base64,iVBORw0KGgo="><body>` + s))

}
