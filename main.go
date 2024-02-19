package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"
)

type oidcConfig struct {
	Provider     string
	ClientID     string
	ClientSecret string
	HostedDomain string

	Alias map[string]alias
}

type alias struct {
	Arn        string
	SourceRole string
	RoleChain  []string
}

var envFormat = flag.Bool("env", false, "output credentials in format suitable for use with $()")

var loginFormat = flag.Bool("login", false, "generate login link for AWS web console")

var verbose = flag.Bool("verbose", false, "log verbose/debug output")

var sourceRole = flag.String("sourcerole", "", "source role to assume before assuming target role")

var aliasFlag = flag.String("alias", "", "alias configured in ~/.oidc2aws/oidcconfig")

var shell = flag.String("shell", "", "shell type, possible values: bash, zsh, sh, fish, csh, tcsh")

func arnFilename(arn string) string {
	arn = strings.Replace(arn, "/", "-", -1)
	arn = strings.Replace(arn, ":", "-", -1)
	return path.Join(os.Getenv("HOME"), ".oidc2aws", arn)
}

func printCredentials(result *result) error {
	if *envFormat {
		// Get the name of current user's default shell
		default_shell := os.Getenv("SHELL")

		current_shell := path.Base(default_shell)

		// If the user has specified a shell, use that instead
		if *shell != "" {
			current_shell = *shell
		}

		// Check the shell type and print the appropriate command to export the variable
		switch current_shell {
		case "fish":
			// For fish, use the set command
			fmt.Printf("set -x AWS_ACCESS_KEY_ID %s\n", *result.Credentials.AccessKeyId)
			fmt.Printf("set -x AWS_SECRET_ACCESS_KEY %s\n", *result.Credentials.SecretAccessKey)
			fmt.Printf("set -x AWS_SESSION_TOKEN %s\n", *result.Credentials.SessionToken)
		case "csh", "tcsh":
			// For csh and tcsh, use the setenv command
			fmt.Printf("setenv AWS_ACCESS_KEY_ID %s\n", *result.Credentials.AccessKeyId)
			fmt.Printf("setenv AWS_SECRET_ACCESS_KEY %s\n", *result.Credentials.SecretAccessKey)
			fmt.Printf("setenv AWS_SESSION_TOKEN %s\n", *result.Credentials.SessionToken)
		case "bash", "zsh", "sh":
			fallthrough
		default:
			// For bash, zsh, sh and any other shell, use the export command
			fmt.Printf("export AWS_ACCESS_KEY_ID=%s\n", *result.Credentials.AccessKeyId)
			fmt.Printf("export AWS_SECRET_ACCESS_KEY=%s\n", *result.Credentials.SecretAccessKey)
			fmt.Printf("export AWS_SESSION_TOKEN=%s\n", *result.Credentials.SessionToken)
		}

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

var debug = func(_ ...interface{}) {}
var debugf = func(_ string, _ ...interface{}) {}

func main() {
	oc := oidcConfig{}

	if _, err := toml.DecodeFile(path.Join(os.Getenv("HOME"), ".oidc2aws", "oidcconfig"), &oc); err != nil {
		log.Fatal(errors.Wrap(err, "error loading OIDC config"))
	}

	flag.Parse()

	if *verbose {
		debug = log.Println
		debugf = log.Printf
	}

	args := flag.Args()

	roles := []string{}

	// 1. len(args) == 1 => initialRole = args[0]
	// 2. len(args) == 1, sourceRole != nil => roles = [sourceRole, ...args] <= legacy
	// 3. alias(arn) => roles = [arn]
	// 4. alias(arn, sourceRole) => initialRole = sourceRole, roles = [sourceRole, arn] <= legacy
	// 5. alias(rolechain) => roles = rolechain
	// 5. len(args) > 1 => roles = args

	if *aliasFlag != "" {
		alias, ok := oc.Alias[*aliasFlag]
		if !ok {
			log.Fatalf("unknown alias: %s", *aliasFlag)
		}
		if len(alias.RoleChain) > 0 {
			roles = alias.RoleChain
		} else {
			if alias.SourceRole != "" {
				roles = []string{alias.SourceRole, alias.Arn}
			} else {
				roles = []string{alias.Arn}
			}
		}
	} else if *sourceRole != "" {
		roles = []string{*sourceRole}
		roles = append(roles, args...)
	} else {
		if len(args) > 0 {
			roles = args
		}
	}

	if len(roles) == 0 {
		log.Fatal("no roles provided, please add roles as args or use -alias")
	}

	var r fetcher = cache{oidcFetcher{arn: roles[0], oc: oc}}
	for _, role := range roles[1:] {
		r = cache{assumedRole{arn: role, upstream: r}}
	}

	result, err := r.fetchCredentials()
	if err != nil {
		log.Fatal(err)
	}

	if err := printCredentials(result); err != nil {
		log.Fatal(errors.Wrap(err, "error printing credentials"))
	}
}

type fetcher interface {
	fetchCredentials() (*result, error)
}

type cacheable interface {
	key() string
}

type expiring interface {
	Expiry() *time.Time
}

type assumedRole struct {
	arn      string
	upstream fetcher
}

func (this assumedRole) fetchCredentials() (*result, error) {
	debugf("assuming role %s", this.arn)
	result, err := this.upstream.fetchCredentials()
	if err != nil {
		return nil, errors.Wrap(err, "error fetching credentials from upstream")
	} else if result == nil {
		return nil, errors.Wrap(err, "upstream didn't return credentials")
	}

	//	return assumeRole(this.arn, idToken.email+","+*result.Credentials.AccessKeyId, result)
	return assumeRole(this.arn, *result.Credentials.AccessKeyId, result)
}

func (this assumedRole) key() string {
	return this.arn
}

type oidcFetcher struct {
	oc  oidcConfig
	arn string
}

func (this oidcFetcher) fetchCredentials() (*result, error) {
	idToken := &idTokenResult{}
	key := "id-token"
	err := get(key, idToken)
	if err != nil && err != errNotFound {
		return nil, errors.Wrap(err, "error reading cached file")
	}

	if err == errNotFound {
		debug("no cached id token, fetching...")
		del(key)
		idToken, err = fetchIDToken(this.oc)
		if err != nil {
			return nil, errors.Wrap(err, "error fetching id token")
		}

		put(key, idToken)
		if err != nil {
			return nil, errors.Wrap(err, "error caching id token")
		}
	} else {
		debug("using cached id token...")
	}

	debugf("swapping id token for credentials for role %s...", this.arn)
	result, err := fetchAWSCredentials(this.arn, idToken.RawToken, idToken.Email)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf(`error fetching aws credentials (is %q an allowed value for "accounts.google.com:sub" in Trust relationship conditions for role?)`, idToken.Sub))
	}
	return result, err
}

func (this oidcFetcher) key() string {
	return this.arn
}

type cacheableFetcher interface {
	cacheable
	fetcher
}

type cache struct {
	f cacheableFetcher
}

func (this cache) fetchCredentials() (*result, error) {
	key := this.f.key()

	// Check for AWS credentials for role, use them if not expired (cache checks expiry)
	result := &result{}
	err := get(key, result)
	if err == nil {
		debugf("have cached credentials for %s", key)

		return result, err
	} else if err != errNotFound {
		return nil, errors.Wrap(err, "error reading cached credentials for role")
	}

	debugf("no cached credentials for %s, fetching...", key)
	result, err = this.f.fetchCredentials()
	if err != nil {
		return nil, errors.Wrap(err, "error fetching credentials")
	}

	put(key, result)
	if err != nil {
		return nil, errors.Wrap(err, "error caching credentials")
	}

	return result, err
}

func put(key string, val interface{}) error {
	debugf("writing credentials for %s to cache", key)

	bytes, err := json.Marshal(val)
	if err != nil {
		return errors.Wrap(err, "error serialising credentials to json")
	}

	err = os.WriteFile(arnFilename(key), bytes, 0600)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("error writing credentials to file %q", key))
	}

	return nil
}

var errNotFound = errors.New("no value for key")

func get(key string, val interface{}) error {
	debugf("fetching cached credentials for %s...", key)
	data, err := os.ReadFile(arnFilename(key))
	if err != nil {
		if os.IsNotExist(err) {
			return errNotFound
		}

		return errors.Wrap(err, fmt.Sprintf("error reading credential cache file %q", key))
	}

	err = json.Unmarshal(data, &val)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("error decoding credential cache from file %q", key))
	}

	exp, ok := val.(expiring)
	debugf("credentials expire at %v", exp.Expiry())
	if expiry := exp.Expiry(); ok && (expiry == nil || exp.Expiry().Add(-5*time.Minute).Before(time.Now())) {
		debug("credentials nil or expiring in less than 5 minutes")
		del(key)
		return errNotFound
	}

	return nil
}

func del(key string) error {
	return os.Remove(arnFilename(key))
}
