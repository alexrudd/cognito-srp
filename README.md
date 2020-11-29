# cognito-srp

[![Build Status](https://travis-ci.org/alexrudd/cognito-srp.svg?branch=master)](https://travis-ci.org/alexrudd/cognito-srp)
[![Go Report Card](https://goreportcard.com/badge/github.com/alexrudd/cognito-srp)](https://goreportcard.com/report/github.com/alexrudd/cognito-srp)
[![Maintainability](https://api.codeclimate.com/v1/badges/30b815a231b657e6ebd6/maintainability)](https://codeclimate.com/github/alexrudd/cognito-srp/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/30b815a231b657e6ebd6/test_coverage)](https://codeclimate.com/github/alexrudd/cognito-srp/test_coverage)

This is almost a direct port of [capless/warrant](https://github.com/capless/warrant/blob/master/warrant/aws_srp.py)

All crypto functions are tested against equivalent values produced by warrant

## v2

The version of this package in the `master` branch makes the assumption that it will be used directly with `aws-sdk-go-v2`. Because of this it intentionally leaks types from the aws package as part of its public API. This has the advantage of reducing code (slightly), but carries the larger disadvantages of complicating dependencies.

It is recommended you use version 2 of this package located in the `v2` branch, though for now both versions will be maintained.

Import v2 of this package with `go get github.com/alexrudd/cognito-srp/v2`and update your imports and code accordingly.

## Usage

```go
package main

import (
    "fmt"
    "time"

    "github.com/alexrudd/cognito-srp/v2"
    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/aws/endpoints"
    "github.com/aws/aws-sdk-go-v2/aws/external"
    cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

func main() {
    // configure cognito srp
    csrp, _ := cognitosrp.NewCognitoSRP("user", "pa55w0rd", "eu-west-1_myPoolId", "client", nil)

    // configure cognito identity provider
    cfg, _ := external.LoadDefaultAWSConfig()
    cfg.Region = endpoints.EuWest1RegionID
    cfg.Credentials = aws.AnonymousCredentials
    svc := cip.New(cfg)

    // initiate auth
    req := svc.InitiateAuthRequest(&cip.InitiateAuthInput{
        AuthFlow:       cip.AuthFlowTypeUserSrpAuth,
        ClientId:       aws.String(csrp.GetClientId()),
        AuthParameters: csrp.GetAuthParams(),
    })
    resp, _ := req.Send()

    // respond to password verifier challenge
    if resp.ChallengeName == cip.ChallengeNameTypePasswordVerifier {
        challengeResponses, _ := csrp.PasswordVerifierChallenge(resp.ChallengeParameters, time.Now())
        chal := svc.RespondToAuthChallengeRequest(&cip.RespondToAuthChallengeInput{
            ChallengeName:      cip.ChallengeNameTypePasswordVerifier,
            ChallengeResponses: challengeResponses,
            ClientId:           aws.String(csrp.GetClientId()),
        })
        resp, _ := chal.Send()

        // print the tokens
        fmt.Println(resp.AuthenticationResult)
    } else {
        // other challenges await...
    }
}
```
