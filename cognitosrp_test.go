package cognitosrp

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func Test_NewCognitoSRP(t *testing.T) {
	csrp, err := NewCognitoSRP("test", "test", "eu-west-1_myPool", "123abd", nil)
	if err != nil {
		t.Fatalf("failed creating CognitoSRP: %s", err.Error())
	}
	// csrp.bigN
	expected, _ := big.NewInt(0).SetString(nHex, 16)
	if csrp.bigN.Cmp(expected) != 0 {
		t.Fatalf("bigN: %v, did not match expected value of: %v", csrp.bigN, expected)
	}

	// csrp.g
	expected, _ = big.NewInt(0).SetString("2", 10)
	if csrp.g.Cmp(expected) != 0 {
		t.Fatalf("g: %v, did not match expected value of: %v", csrp.g, expected)
	}
	// csrp.k
	expected, _ = big.NewInt(0).SetString("37772559067617796309459009502931177628717927509759535181635788491848250400486", 10)
	if csrp.k.Cmp(expected) != 0 {
		t.Fatalf("k: %v, did not match expected value of: %v", csrp.k, expected)
	}
	// csrp.a - is random so lets set it and re-calculate A
	csrp.a = big.NewInt(1234567890)
	csrp.bigA = csrp.calculateA()
	// csrp.bigA
	expected, _ = big.NewInt(0).SetString("2012821450179237266067414751941060928019817287314017835667297413615441680042015648893619512074574801551816908048875039310556108650595869145768432324376774060555385775073708569121688902158895642383219736852216366144529156744028151458424436810791218362729260005923018973559621869173270335133101064964177433161771074465994401225946602823489327809869650103314918749719145076380535976325009253493972634191523079035525341598366462733532137597586069288340594563327421244726332307232609401008335819089778907622323610696065668900966210610871808610884224270017149857647788822043386341947275701612494162630191389615660619561655481399573723311377577792260581174997618956152489507325218699555095233121100546572188701563979417701865276739418278601329844176326814813849675127887644523181751359470351143169066091784103404544366711287145804238613966547260918328728126017769114261057445005776403447691297001659393612551419207658913838531096191", 10)
	if csrp.bigA.Cmp(expected) != 0 {
		t.Fatalf("A: %v, did not match expected value of: %v", csrp.bigA, expected)
	}

	// build a bad csrp
	_, err = NewCognitoSRP("test", "test", "myPool", "123abd", nil)
	if err == nil {
		t.Fatalf("PasswordVerifierChallenge should error on bad 'SECRET_BLOCK'")
	}
}

func Test_Getters(t *testing.T) {
	csrp, _ := NewCognitoSRP("user1", "pa55w0rd", "eu-west-1_myPool", "123abd", nil)

	if csrp.GetUsername() != "user1" {
		t.Fatalf("actual username: %s, did not match expected username: %s", csrp.GetUsername(), "user1")
	}
	if csrp.GetClientId() != "123abd" {
		t.Fatalf("actual client ID: %s, did not match expected client ID: %s", csrp.GetUsername(), "123abd")
	}
	if csrp.GetUserPoolId() != "eu-west-1_myPool" {
		t.Fatalf("actual pool ID: %s, did not match expected pool ID: %s", csrp.GetUsername(), "eu-west-1_myPool")
	}
	if csrp.GetUserPoolName() != "myPool" {
		t.Fatalf("actual pool name: %s, did not match expected pool name: %s", csrp.GetUsername(), "myPool")
	}
}

func Test_GetAuthParams(t *testing.T) {
	cs := "clientSecret"
	csrp, _ := NewCognitoSRP("test", "test", "eu-west-1_myPool", "123abd", &cs)
	csrp.a = big.NewInt(1234567890)
	csrp.bigA = csrp.calculateA()

	params := csrp.GetAuthParams()

	if params["USERNAME"] != csrp.username {
		t.Fatalf("actual USERNAME: %s, did not match expected USERNAME: %s", params["USERNAME"], csrp.username)
	}
	if params["SRP_A"] != csrp.bigA.Text(16) {
		t.Fatalf("actual SRP_A: %s, did not match expected SRP_A: %s", params["SRP_A"], csrp.bigA.Text(16))
	}
	expectedHash := "LoIX/oPJWZzFYv8liJYRo+CHv16FNDY10JlZEDjL3Vg="
	if params["SECRET_HASH"] != expectedHash {
		t.Fatalf("actual SECRET_HASH: %s, did not match expected SECRET_HASH: %s", params["SECRET_HASH"], expectedHash)
	}
}

func Test_GetSecretHash(t *testing.T) {
	// with secret
	cs := "clientSecret"
	csrp, _ := NewCognitoSRP("test", "test", "eu-west-1_myPool", "123abd", &cs)

	hash, err := csrp.GetSecretHash("test")
	if err != nil {
		return
	}
	expectedHash := "LoIX/oPJWZzFYv8liJYRo+CHv16FNDY10JlZEDjL3Vg="
	if hash != expectedHash {
		t.Fatalf("actual hash: %s, did not match expected hash: %s", hash, expectedHash)
	}

	csrp.clientSecret = nil
	_, err = csrp.GetSecretHash("test")
	if err == nil {
		t.Fatal("GetSecretHash should error on nil client secret")
	}
}

func Test_PasswordVerifierChallenge(t *testing.T) {
	cs := "clientSecret"
	csrp, _ := NewCognitoSRP("test", "test", "eu-west-1_myPool", "123abd", &cs)
	csrp.a = big.NewInt(1234567890)
	csrp.bigA = csrp.calculateA()
	challengeParmas := map[string]string{
		"USER_ID_FOR_SRP": "test",
		"SALT":            big.NewInt(1234567890).Text(16),
		"SRP_B":           big.NewInt(1234567890).Text(16),
		"SECRET_BLOCK":    base64.StdEncoding.EncodeToString([]byte("secretssecrestssecrets")),
	}

	reqin, _ := csrp.PasswordVerifierChallenge(challengeParmas, time.Date(2018, 7, 10, 11, 1, 0, 0, time.UTC))

	expected := "tdvQu/Li/qWl8Nni0aFPs+MwY4rvKZm0kSMrGIMSUHk="
	if reqin.ChallengeResponses["PASSWORD_CLAIM_SIGNATURE"] != expected {
		t.Fatalf("actual PASSWORD_CLAIM_SIGNATURE: %s, did not match expected PASSWORD_CLAIM_SIGNATURE: %s", reqin.ChallengeResponses["PASSWORD_CLAIM_SIGNATURE"], expected)
	}

	// Bad challenge params
	challengeParmas["SECRET_BLOCK"] = "not base64 encoded"
	_, err := csrp.PasswordVerifierChallenge(challengeParmas, time.Date(2018, 7, 10, 11, 46, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("PasswordVerifierChallenge should error on bad 'SECRET_BLOCK'")
	}
}

func Test_calculateA(t *testing.T) {
	csrp, _ := NewCognitoSRP("test", "test", "eu-west-1_myPool", "123abd", nil)
	// test panic
	csrp.g = big.NewInt(0)
	defer func() {
		errmsg := recover().(string)
		if errmsg != "Safety check for A failed. A must not be divisable by N" {
			t.Fatalf("Wrong panic message: %s", errmsg)
		}
	}()
	csrp.calculateA()
	t.Fatal("calculateA did not panic on 0 g value")
}

func Test_getPasswordAuthenticationKey(t *testing.T) {
	cs := "clientSecret"
	csrp, _ := NewCognitoSRP("test", "test", "eu-west-1_myPool", "123abd", &cs)
	bigB := big.NewInt(1234567890)
	salt := big.NewInt(1234567890)
	csrp.a = big.NewInt(1234567890)
	csrp.bigA = csrp.calculateA()

	expectedBigA, _ := big.NewInt(0).SetString("2012821450179237266067414751941060928019817287314017835667297413615441680042015648893619512074574801551816908048875039310556108650595869145768432324376774060555385775073708569121688902158895642383219736852216366144529156744028151458424436810791218362729260005923018973559621869173270335133101064964177433161771074465994401225946602823489327809869650103314918749719145076380535976325009253493972634191523079035525341598366462733532137597586069288340594563327421244726332307232609401008335819089778907622323610696065668900966210610871808610884224270017149857647788822043386341947275701612494162630191389615660619561655481399573723311377577792260581174997618956152489507325218699555095233121100546572188701563979417701865276739418278601329844176326814813849675127887644523181751359470351143169066091784103404544366711287145804238613966547260918328728126017769114261057445005776403447691297001659393612551419207658913838531096191", 10)

	if csrp.bigA.Cmp(expectedBigA) != 0 {
		t.Fatalf("A: %v, did not match expected value of: %v", csrp.bigA, expectedBigA)
	}

	expectedKey := "d96cde6c95dda17175c1293140c5a81f"
	key := csrp.getPasswordAuthenticationKey(csrp.username, csrp.password, bigB, salt)
	keyHex := hex.EncodeToString(key)
	if keyHex != expectedKey {
		t.Fatalf("actual key: %s, did not match expected key: %s", keyHex, expectedKey)
	}
}

func Test_hashSha256(t *testing.T) {
	in := "testvalue"
	expectedOut := "b52ccfce5067e90f4b4f8ec8567eb50f9e10850d6e114a2ea09cb45f753011b9"
	out := hashSha256([]byte(in))
	if out != expectedOut {
		t.Fatalf("actual out: %s, did not match expected out: %s", out, expectedOut)
	}
}

func Test_hexHash(t *testing.T) {
	in := "testvalue"
	in = hex.EncodeToString([]byte(in))
	expectedOut := "b52ccfce5067e90f4b4f8ec8567eb50f9e10850d6e114a2ea09cb45f753011b9"
	out := hexHash(in)
	if out != expectedOut {
		t.Fatalf("actual out: %s, did not match expected out: %s", out, expectedOut)
	}
}

func Test_hexToBig(t *testing.T) {
	in := "499602d2"
	expectedOut := big.NewInt(1234567890)
	out := hexToBig(in)
	if out.Cmp(expectedOut) != 0 {
		t.Fatalf("actual out: %v, did not match expected out: %v", out, expectedOut)
	}

	// test panic
	in = "non-hex input"
	defer func() {
		errmsg := recover().(string)
		if errmsg != fmt.Sprintf("unable to covert \"%s\" to big Int", in) {
			t.Fatalf("Wrong panic message: %s", errmsg)
		}
	}()
	hexToBig(in)
	t.Fatal("hexToBig did not panic on non-hex input")
}

func Test_bigToHex(t *testing.T) {
	in := big.NewInt(1234567890)
	expectedOut := "499602d2"
	out := bigToHex(in)
	if out != expectedOut {
		t.Fatalf("actual out: %v, did not match expected out: %v", out, expectedOut)
	}
}

func Test_padHex(t *testing.T) {
	in := "123abc"
	expectedOut := "123abc"
	out := padHex(in)
	if out != expectedOut {
		t.Fatalf("actual out: %s, did not match expected out: %s", out, expectedOut)
	}

	in = "123abcd"
	expectedOut = "0123abcd"
	out = padHex(in)
	if out != expectedOut {
		t.Fatalf("actual out: %s, did not match expected out: %s", out, expectedOut)
	}

	in = "8123abcd"
	expectedOut = "008123abcd"
	out = padHex(in)
	if out != expectedOut {
		t.Fatalf("actual out: %s, did not match expected out: %s", out, expectedOut)
	}
}

func Test_computeHKDF(t *testing.T) {
	inIkm, inSalt := "00cf724779a05d41df17a315d188ce565d0bc7a70e6bc4199ad3959a531c6b4ca4b9ac31f639b96391a2f8d28c7d47d9759fc7a23a59bfb95691147b212b050116cf53fa1a7876ef179003dea92b246bc9584240d3e5a294a158b12cc92642bbe5c7d854338233f54fd66f10384b3d3e740280017773feb1104696bfe6e0a82ec5ef2fc23fad663f5e945e8644c872d05f4ab7961436d0602c961d1619e91b70e451f0769e80b0d6ae80052ed47c3c89f4caae02ff01917f195b8cbea78f895da7145646e64b63605a7ffd85de351c06a5a5ffb6eee8b392b4d137726468361bbcf7b4055600002ae7c8c1dd5c545862f1c4c725c01da795afab3221d322104aecd4d1ab74d5e81eb45cbdb52081b1413a9e8b08e76b961c74cdbdac017d8d22a24860a674a0cd526e8ff8403caac07c0c720636efd83291ae60ff15cbd0a881f8030495cae0327040855defba70625c78cf27ea50bcaf0322cac01cf753c5a34269e4e329c9cd388aada7781cf1c552754a0d2d3ce5fe58198a31b7b0ddc515ad", "0c98b195a479d1a7c70c99dd680f34f5805fe686d0bc716549ff2ed895aa9111"
	expectedOut := "d96cde6c95dda17175c1293140c5a81f"
	out := hex.EncodeToString([]byte(computeHKDF(inIkm, inSalt)))
	if out != expectedOut {
		t.Fatalf("actual out: %v, did not match expected out: %v", out, expectedOut)

	}
}

func Test_calculateU(t *testing.T) {
	inA, _ := big.NewInt(0).SetString("6D797365637265746861736841", 16)
	inB, _ := big.NewInt(0).SetString("6D797365637265746861736842", 16)
	expectedOut, _ := big.NewInt(0).SetString("39743664823761398449876968619416475559594078623923024211668626611155104513539", 10)
	out := calculateU(inA, inB)
	if out.Cmp(expectedOut) != 0 {
		t.Fatalf("actual out: %v, did not match expected out: %v", out, expectedOut)
	}
}
