# cognito-srp

[![Build Status](https://travis-ci.org/alexrudd/cognito-srp.svg?branch=master)](https://travis-ci.org/alexrudd/cognito-srp)
[![Go Report Card](https://goreportcard.com/badge/github.com/alexrudd/cognito-srp)](https://goreportcard.com/report/github.com/alexrudd/cognito-srp)
[![Maintainability](https://api.codeclimate.com/v1/badges/30b815a231b657e6ebd6/maintainability)](https://codeclimate.com/github/alexrudd/cognito-srp/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/30b815a231b657e6ebd6/test_coverage)](https://codeclimate.com/github/alexrudd/cognito-srp/test_coverage)

This is almost a direct port of [capless/warrant](https://github.com/capless/warrant/blob/master/warrant/aws_srp.py)

All crypto functions are tested against equivalent values produced by warrant

* v2 - Removed dependency on `aws-sdk-go-v2`
* v3 - Package and usage have been updated to improve compatibility with latest `aws-sdk-go-v2` API

## Usage

```go
package main

import (
	"context"
	"fmt"
	"time"

	cognitosrp "github.com/alexrudd/cognito-srp/v3"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

func main() {
	// configure cognito srp
	csrp, _ := cognitosrp.NewCognitoSRP("user", "pa55w0rd", "eu-west-1_myPoolId", "client", nil)

	// configure cognito identity provider
	cfg, _ := config.LoadDefaultConfig(
		config.WithRegion("eu-west-1"),
		config.WithCredentialsProvider(aws.AnonymousCredentials{}),
	)
	svc := cip.NewFromConfig(cfg)

	// initiate auth
	resp, err := svc.InitiateAuth(context.Background(), &cip.InitiateAuthInput{
		AuthFlow:       types.AuthFlowTypeUserSrpAuth,
		ClientId:       aws.String(csrp.GetClientId()),
		AuthParameters: csrp.GetAuthParams(),
	})
	if err != nil {
		panic(err)
	}

	// respond to password verifier challenge
	if resp.ChallengeName == types.ChallengeNameTypePasswordVerifier {
		challengeResponses, _ := csrp.PasswordVerifierChallenge(resp.ChallengeParameters, time.Now())

		resp, err := svc.RespondToAuthChallenge(context.Background(), &cip.RespondToAuthChallengeInput{
			ChallengeName:      types.ChallengeNameTypePasswordVerifier,
			ChallengeResponses: challengeResponses,
			ClientId:           aws.String(csrp.GetClientId()),
		})
		if err != nil {
			panic(err)
		}

		// print the tokens
		fmt.Printf("Access Token: %s\n", *resp.AuthenticationResult.AccessToken)
		fmt.Printf("ID Token: %s\n", *resp.AuthenticationResult.IdToken)
		fmt.Printf("Refresh Token: %s\n", *resp.AuthenticationResult.RefreshToken)
	} else {
		// other challenges await...
	}
}
```