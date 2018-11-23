package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/coreos/go-oidc"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type oidcConfig struct {
	Provider     string
	ClientID     string
	ClientSecret string
	HostedDomain string
}

type idTokenResult struct {
	rawToken string
	token    *oidc.IDToken
	email    string
	sub      string
}

type idTokenMessage struct {
	result idTokenResult
	err    error
}

var envFormat = flag.Bool("env", false, "output credentials in format suitable for use with $()")

func fetchIDToken() (*idTokenResult, error) {
	oc := oidcConfig{}

	if _, err := toml.DecodeFile(path.Join(os.Getenv("HOME"), ".oidc2aws", "oidcconfig"), &oc); err != nil {
		return nil, errors.Wrap(err, "error loading OIDC config")
	}

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
	cmd := exec.Command("open", url)
	if err := cmd.Run(); err != nil {
		return nil, errors.Wrap(err, "error opening page in browser")
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
				rawToken: rawIDToken,
				token:    idToken,
				email:    claims.Email,
				sub:      claims.Subject,
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

type result struct {
	Version int
	sts.Credentials
}

func fetchAWSCredentials(arn, token, sessionName string) (*result, error) {

	input := sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          &arn,
		RoleSessionName:  &sessionName,
		WebIdentityToken: &token,
	}

	sess, err := session.NewSession()
	if err != nil {
		return nil, errors.Wrap(err, "error creating aws session")
	}

	svc := sts.New(sess)
	output, err := svc.AssumeRoleWithWebIdentity(&input)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("error assuming role %q with web identity", arn))
	}

	result := result{
		Version:     1,
		Credentials: *output.Credentials,
	}

	bytes, err := json.Marshal(result)
	if err != nil {
		return nil, errors.Wrap(err, "error serialising credentials to json")
	}

	filename := arnFilename(arn)

	err = ioutil.WriteFile(filename, bytes, 0600)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("error writing credentials to file %q", filename))
	}

	return &result, nil
}

func arnFilename(arn string) string {
	arn = strings.Replace(arn, "/", "-", -1)
	arn = strings.Replace(arn, ":", "-", -1)
	return path.Join(os.Getenv("HOME"), ".oidc2aws", arn)
}

func credentialsForRole(arn string) (*result, error) {
	result := result{}

	filename := arnFilename(arn)

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, errors.Wrap(err, fmt.Sprintf("error reading credential cache file %q", filename))
	}

	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("error decoding credential cache from file %q", filename))
	}

	// check token expires > 5 minutes from now
	if result.Expiration == nil {
		return nil, nil
	} else if (*result.Expiration).Add(-5 * time.Minute).Before(time.Now()) {
		err := os.Remove(filename)
		if err != nil {
			err = errors.Wrap(err, fmt.Sprintf("error removing expired credentials in file %q", filename))
		}
		return nil, err
	}

	return &result, nil
}

func printCredentials(result *result) error {
	if !*envFormat {
		b, err := json.Marshal(result)
		if err != nil {
			return errors.Wrap(err, "error serialising credentials to json")
		}

		// Write credentials to stdout
		_, err = os.Stdout.Write(b)

		return err
	}
	fmt.Printf("export AWS_ACCESS_KEY_ID=%s\n", *result.Credentials.AccessKeyId)
	fmt.Printf("export AWS_SECRET_ACCESS_KEY=%s\n", *result.Credentials.SecretAccessKey)
	fmt.Printf("export AWS_SESSION_TOKEN=%s\n", *result.Credentials.SessionToken)
	return nil
}

func main() {

	flag.Parse()

	args := flag.Args()

	arn := ""
	if len(args) > 0 {
		arn = args[0]
	}

	if arn == "" {
		log.Fatal("no arn provided in Args[1]")
	}

	// Check for AWS credentials for role, use them if not expired
	result, err := credentialsForRole(arn)
	if err != nil {
		log.Fatal(errors.Wrap(err, "error reading credentials for role"))
	} else if result != nil {
		err := printCredentials(result)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	// Check for ID Token, use it if not expired
	// Fetch ID token
	// Cache ID token
	// Fetch AWS credentials

	idToken, err := fetchIDToken()
	if err != nil {
		log.Fatal(errors.Wrap(err, "error fetching id token"))
	}

	result, err = fetchAWSCredentials(arn, idToken.rawToken, idToken.email)
	if err != nil {
		log.Fatal(errors.Wrap(err, fmt.Sprintf(`error fetching aws credentials (is %q an allowed value for "accounts.google.com:sub" in Trust relationship conditions for role?)`, idToken.sub)))
	}

	if err := printCredentials(result); err != nil {
		log.Fatal(errors.Wrap(err, "error printing credentials"))
	}
}
