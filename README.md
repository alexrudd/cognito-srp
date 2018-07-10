# cognito-srp

This is almost a direct port of [capless/warrant](https://github.com/capless/warrant/blob/master/warrant/aws_srp.py)

All crypto functions are tested against equivalent values produced by warrant

## Usage

```go
package main

import (
	"fmt"
	"time"

	"github.com/alexrudd/cognito-srp"
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
		challengeInput, _ := csrp.PasswordVerifierChallenge(resp.ChallengeParameters, time.Now())
		chal := svc.RespondToAuthChallengeRequest(challengeInput)
		resp, _ := chal.Send()

		// print the tokens
		fmt.Println(resp.AuthenticationResult)
	} else {
		// other challenges await...
	}
}
```
