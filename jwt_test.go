package jwt

import (
	"testing"
	"time"
	"strings"
)

type testAuthenticationBody struct {
	UserName string
	Age int
	CreationDate time.Time
}

func Test_GenerateHS256Token_Success(t *testing.T) {

	payload := testAuthenticationBody{UserName: "test", Age: 33, CreationDate: time.Now()}
	secret := "this is my secret"

	token, err := Encode(payload, secret, "HS256")

	if err != nil {
		t.Errorf("Got unexpected error: %s", err.Error())
		t.Fail()
	}

	if token == "" {
		t.Error("Empty token generated")
		t.Fail()
	}

	if strings.Count(token, ".") != 2 {
		t.Errorf("Expect 3 part token, got %d", strings.Count(token, "."))
		t.Fail()
	}
	
}

func Test_GenerateHS512Token_Success(t *testing.T) {
	payload := testAuthenticationBody{UserName: "test", Age: 33, CreationDate: time.Now()}
	secret := "this is my secret for HS512"

	token, err := Encode(payload, secret, "HS512")

	if err != nil {
		t.Errorf("Got unexpected error: %s", err.Error())
		t.Fail()
	}

	if token == "" {
		t.Error("Empty token generated")
		t.Fail()
	}

	if strings.Count(token, ".") != 2 {
		t.Errorf("Expect 3 part token, got %d", strings.Count(token, "."))
		t.Fail()
	}
}

func Test_GenerateInvalidAlgorithm_GivesError(t *testing.T) {
	payload := testAuthenticationBody{UserName: "test", Age: 33, CreationDate: time.Now()}
	secret := "this is my secret for invalid"

	_, err := Encode(payload, secret, "HS12131")

	if err == nil {
		t.Error("Expected failure as algorithm is invalid")
		t.Fail()
	}
}

func Test_DecodeHS256Token_Success(t *testing.T) {

	secret := "this is my secret"
	payload := testAuthenticationBody{UserName: "test", Age: 33, CreationDate: time.Now()}

	token, err := Encode(payload, secret, "HS256")

	var payload2 testAuthenticationBody

	err = Decode(token, secret, &payload2)

	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
		t.Fail()
	}

	if payload2.UserName == "" {
		t.Error("Payload not expected to be null")
		t.Fail()
	}

	if payload2.Age == 0 {
		t.Error("Payload not expected to be null")
		t.Fail()
	}

	if payload2.CreationDate.IsZero() {
		t.Error("Payload not expected to be null")
		t.Fail()
	}

}


func Test_DecodeHS512Token_Success(t *testing.T) {

	secret := "this is my secret"
	payload := testAuthenticationBody{UserName: "test", Age: 33, CreationDate: time.Now()}

	token, err := Encode(payload, secret, "HS512")

	var payload2 interface{}

	err = Decode(token, secret, &payload2)

	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
		t.Fail()
	}

}

func Test_DecodeHS256TokenMissingHeader_GivesError(t *testing.T) {
	token := ".eyJVc2VyTmFtZSI6InRlc3QiLCJBZ2UiOjMzLCJDcmVhdGlvbkRhdGUiOiIyMDIwLTA2LTEwVDE3OjU5OjA5LjYzMjQ5Mi0wNzowMCJ9.JH3K9upbznHSw7WB0zcwZ3plvJ7_huDoWoG66JwL9yg"
	secret := "this is my secret"

	var payload testAuthenticationBody

	err := Decode(token, secret, &payload)

	if err == nil {
		t.Error("Expected error but got success")
		t.Fail()
	}


}

func Test_DecodeHS256TokenMissingSigningInput_GivesError(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..JH3K9upbznHSw7WB0zcwZ3plvJ7_huDoWoG66JwL9yg"
	secret := "this is my secret"

	var payload testAuthenticationBody

	err := Decode(token, secret, &payload)

	if err == nil {
		t.Error("Expected error but got success")
		t.Fail()
	}


}

func Test_DecodeHS256TokenMissingSignature_GivesError(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VyTmFtZSI6InRlc3QiLCJBZ2UiOjMzLCJDcmVhdGlvbkRhdGUiOiIyMDIwLTA2LTEwVDE3OjU5OjA5LjYzMjQ5Mi0wNzowMCJ9."
	secret := "this is my secret"

	var payload testAuthenticationBody

	err := Decode(token, secret, &payload)

	if err == nil {
		t.Error("Expected error but got success")
		t.Fail()
	}


}

func Test_DecodeHS256InvalidSignature_GivesError(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VyTmFtZSI6InRlc3QiLCJBZ2UiOjMzLCJDcmVhdGlvbkRhdGUiOiIyMDIwLTA2LTEwVDE3OjU5OjA5LjYzMjQ5Mi0wNzowMCJ9.JH3K9upbznHSw7WB0zcwZ3plvJ7_huDoWoG66JwL9yg"
	secret := "this is my secretXXXXX"

	var payload testAuthenticationBody

	err := Decode(token, secret, &payload)

	if err == nil {
		t.Error("Expected error but got success")
		t.Fail()
	}
}

func Test_DecodeHS512TokenMissingHeader_GivesError(t *testing.T) {
	token := ".eyJVc2VyTmFtZSI6InRlc3QiLCJBZ2UiOjMzLCJDcmVhdGlvbkRhdGUiOiIyMDIwLTA2LTEwVDE4OjAzOjUwLjk1NzkxNy0wNzowMCJ9.WjEPNQE9Jo3D7KpUBnvN_aGqvC4A8xBrOYYYf3vNa47i75_kjOOZINXyi_uyx8KJ8XojxD_lb_sfS6u4SM8zJw"
	secret := "this is my secret for HS512"

	var payload testAuthenticationBody

	err := Decode(token, secret, &payload)

	if err == nil {
		t.Error("Expected error but got success")
		t.Fail()
	}
}

func Test_DecodeHS512TokenMissingSigningInput_GivesError(t *testing.T) {
	token := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9..WjEPNQE9Jo3D7KpUBnvN_aGqvC4A8xBrOYYYf3vNa47i75_kjOOZINXyi_uyx8KJ8XojxD_lb_sfS6u4SM8zJw"
	secret := "this is my secret for HS512"

	var payload testAuthenticationBody

	err := Decode(token, secret, &payload)

	if err == nil {
		t.Error("Expected error but got success")
		t.Fail()
	}
}

func Test_DecodeHS512TokenMissingSignature_GivesError(t *testing.T) {
	token := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJVc2VyTmFtZSI6InRlc3QiLCJBZ2UiOjMzLCJDcmVhdGlvbkRhdGUiOiIyMDIwLTA2LTEwVDE4OjAzOjUwLjk1NzkxNy0wNzowMCJ9."
	secret := "this is my secret for HS512"

	var payload testAuthenticationBody

	err := Decode(token, secret, &payload)

	if err == nil {
		t.Error("Expected error but got success")
		t.Fail()
	}
}

func Test_DecodeHS512InvalidSignature_GivesError(t *testing.T) {
	token := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJVc2VyTmFtZSI6InRlc3QiLCJBZ2UiOjMzLCJDcmVhdGlvbkRhdGUiOiIyMDIwLTA2LTEwVDE4OjAzOjUwLjk1NzkxNy0wNzowMCJ9.WjEPNQE9Jo3D7KpUBnvN_aGqvC4A8xBrOYYYf3vNa47i75_kjOOZINXyi_uyx8KJ8XojxD_lb_sfS6u4SM8zJw"
	secret := "this is my secret for HS512abc"

	var payload testAuthenticationBody

	err := Decode(token, secret, &payload)

	if err == nil {
		t.Error("Expected error but got success")
		t.Fail()
	}
}