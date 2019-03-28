package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/aws/aws-sdk-go/aws"
	awscreds "github.com/aws/aws-sdk-go/aws/credentials"
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

var loginFormat = flag.Bool("login", false, "generate login link for AWS web console")

var sourceRole = flag.String("sourcerole", "", "source role to assume before assuming target role")

func openInBrowser(url string) error {
	cmd := exec.Command("open", url)
	return errors.Wrap(cmd.Run(), "error opening page in browser")
}

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

func assumeRole(arn, sessionName string, credentials *result) (*result, error) {

	input := sts.AssumeRoleInput{
		RoleArn:         &arn,
		RoleSessionName: &sessionName,
	}

	sess, err := session.NewSession(
		aws.NewConfig().WithCredentials(
			awscreds.NewStaticCredentials(
				*credentials.Credentials.AccessKeyId,
				*credentials.Credentials.SecretAccessKey,
				*credentials.Credentials.SessionToken,
			)))
	if err != nil {
		return nil, errors.Wrap(err, "error creating aws session")
	}

	svc := sts.New(sess)
	output, err := svc.AssumeRole(&input)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("error assuming role %q", arn))
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

type signinSession struct {
	SessionId    string `json:"sessionId"`
	SessionKey   string `json:"sessionKey"`
	SessionToken string `json:"sessionToken"`
}

type signinToken struct {
	SigninToken string
}

// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html
func fetchSigninToken(result *result) error {

	sessionData := signinSession{
		SessionId:    *result.Credentials.AccessKeyId,
		SessionKey:   *result.Credentials.SecretAccessKey,
		SessionToken: *result.Credentials.SessionToken,
	}

	b, err := json.Marshal(sessionData)

	if err != nil {
		return errors.Wrap(err, "failed to encode signin json data")
	}

	tokenURL := fmt.Sprintf("https://signin.aws.amazon.com/federation?Action=getSigninToken&Session=%s", url.QueryEscape(string(b)))

	resp, err := http.DefaultClient.Get(tokenURL)
	if err != nil {
		return errors.Wrap(err, "failed to fetch signin token for credentials")
	} else if resp.StatusCode != 200 {
		return fmt.Errorf("getSigninToken returned %d instead of 200", resp.StatusCode)
	}

	buffer := new(bytes.Buffer)
	buffer.ReadFrom(resp.Body)
	token := signinToken{}
	err = json.Unmarshal(buffer.Bytes(), &token)
	if err != nil {
		return errors.Wrap(err, "failed to decode getSigninToken response")
	}

	destination := "https://console.aws.amazon.com/"

	loginUrl := fmt.Sprintf("https://signin.aws.amazon.com/federation?Action=login&Destination=%s&SigninToken=%s",
		url.QueryEscape(destination),
		token.SigninToken,
	)

	if err := openInBrowser(loginUrl); err != nil {
		return err
	}

	return nil
}

func printCredentials(result *result) error {
	if *envFormat {
		fmt.Printf("export AWS_ACCESS_KEY_ID=%s\n", *result.Credentials.AccessKeyId)
		fmt.Printf("export AWS_SECRET_ACCESS_KEY=%s\n", *result.Credentials.SecretAccessKey)
		fmt.Printf("export AWS_SESSION_TOKEN=%s\n", *result.Credentials.SessionToken)
		return nil
	} else if *loginFormat {
		return fetchSigninToken(result)
	}

	b, err := json.Marshal(result)
	if err != nil {
		return errors.Wrap(err, "error serialising credentials to json")
	}

	// Write credentials to stdout
	_, err = os.Stdout.Write(b)

	return err
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

	if *sourceRole == "" {
		*sourceRole = arn
	}

	idToken, err := fetchIDToken()
	if err != nil {
		log.Fatal(errors.Wrap(err, "error fetching id token"))
	}

	result, err = fetchAWSCredentials(*sourceRole, idToken.rawToken, idToken.email)
	if err != nil {
		log.Fatal(errors.Wrap(err, fmt.Sprintf(`error fetching aws credentials (is %q an allowed value for "accounts.google.com:sub" in Trust relationship conditions for role?)`, idToken.sub)))
	}

	if *sourceRole != arn {
		result, err = assumeRole(arn, idToken.email+","+*result.Credentials.AccessKeyId, result)
		if err != nil {
			log.Fatal(err)
		}
	}

	if err := printCredentials(result); err != nil {
		log.Fatal(errors.Wrap(err, "error printing credentials"))
	}
}
