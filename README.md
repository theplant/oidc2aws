# Overview

This program generates credentials for use by the AWS CLI, backed by
STS `assumeRoleWithWebIdentity` and an OIDC provider.

## Process Overview

1. Use `aws <command>`.

2. AWS uses `oidc2aws` as a `credential_process` to request
   credentials for a profile (+ Role ARN).

3. `oidc2aws` checks for unexpired cached credentials for a Role
   ARN. If found, they are passed back to `aws`.

4. If no unexpired credentials are cached, `oidc2aws` starts a
   web-server and, open the user's browser pointed to a configured
   OAuth app.

5. User authenticates with Google and authorises the OAuth app to
   access the Google account details.

6. Google passes an authorisation code back to the web-server started
   in step 4 by redirection the user's browser.

7. The web-server handles the redirection, swaps the authorisation
   code for access and ID tokens, and terminates the web-server.

8. `oidc2aws` then uses the ID token with the AWS STS API to assume
   the given role.

9. Credentials generated in step 8 are passed back to `aws` for use
   with the originally-requested AWS CLI/API call.

# Setup with G Suite

## 1. Configure Google OAuth Application

Create an OAuth 2.0 Client in Google Cloud console, and:

1. Set *Authorised redirect URIs* to `http://localhost:9999/code`

2. Mark application as *Internal* on *OAuth consent screen*.

3. Make note of client ID and secret.


## 2. Create `oidc2aws` config file

Create a file in `$HOME/.oidc2aws/oidcconfig`, with contents of:

```
Provider = "https://accounts.google.com"
ClientID = "<client ID>"
ClientSecret = "<client secret>"
```

## 3. Create AWS IAM Role

Create an *Identity provider* in AWS IAM;

1. *Provider Type*: *OpenID Connect*

2. *Provider URL*: `https://accounts.google.com`

3. *Audience*: Client ID of OAuth 2.0 app created above.

Create new role in AWS IAM to be used with `oidc2aws`:

1. *Select type of trusted entity*: *Web identity*.

2. *Identity provider*: use provider created earlier (or choose
   *Google*).

3. *Audience*: Select *Audience* added when creating provider (or use
   Client ID directly)

4. **Do not attach any policies yet**. When you first create the role,
   *anyone who can log in to the OAuth* application can assume the
   role.

To restrict access to the role:

1. Go to the details for the role you just created, select the *Trust
   relationships* tab, and click *Edit trust relationship*.

2. Add a `StringEquals` (or `ForAllValues:StringEquals`) field to
   `Conditions`. The value should be an object that looks like:

   ```
   "StringEquals": {
     "accounts.google.com:sub": "<Google ID>"
   }
   ```

   Determining someone's Google ID can be a bit tricky, and I'm not
   going to write instructions on how to find this out yet :E

Once you've restricted access to the role, you can attach policies to
the role as usual.

## 4. Configure AWS CLI to use `oidc2aws` to fetch credentials.

Make a note of the ARN for the role you created in the previous step.

edit `$HOME/.config`, and add a profile section:

```
[profile my-profile]
credential_process = oidc2aws <role arn:aws:iam::123456789012:role/my-role>
```

Then you should be able to use the AWS CLI:

```
$ aws --profile=my-profile sts get-caller-identity
{
    "UserId": "AROAXXXXXXXXXXXXXXXX:me@example.com",
    "Account": "123456789012",
    "Arn": "arn:aws:sts::123456789012:assumed-role/my-role/me@example.com"
}
```

# Caveats

* The username used when assuming the role is under control of the
  client (meaning that `oidc2aws` arbitrarily sets it to the email
  address of the user), and is not a reliable indicator of the user's
  identity in AWS (meaning it would be trivial to spoof it to be
  someone else's email address). 

  You can determine the true G Suite account used by looking at the
  API event data in CloudTrail in
  `userIdentity.sessionContext.webIdFederationData.attributes.accounts.google.com:sub`.

* AWS credentials are cached in plain-text at rest in
  `$HOME/.oidc2aws/<role name>`. Our original requirement was to
  eliminate use of permanent credentials, so this is acceptable to us
  as the on-disk credentials expire in < 12 hours.

# Ideas for improvement

* Cache the G Suite ID token similarly to how the AWS credentials are
  cached.

* Encrypt or otherwise harden the storage of AWS credentials at rest.

* Find a better way to manage G Suite user to AWS role mapping. Google
  account IDs are hard to discover/audit, and if you don't add a
  condition on the *Trusted entity*, by default *anyone* who can use
  the OAuth app can assume the AWS role.

* Review the system design to identify flaws in the security model.

# Background

To eliminate the use of permanent AWS credentials, we looked at
migrating to federated authn/z. SAML integration between AWS and G
Suite is quite good, but it provides nothing in the way of support for
using the AWS CLI.
