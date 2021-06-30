package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	awscreds "github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
)

type result struct {
	Version int
	sts.Credentials
}

func (this result) Expiry() *time.Time {
	return this.Expiration
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
