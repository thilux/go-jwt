package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"log"
	"encoding/base64"
	"encoding/json"
	"strings"
)

const tokenType = "JWT"

//HS256 instance of a sh256 hash algorithm
var HS256 = sha256.New

//HS512 instance of a sh512 hash algorithm
var HS512 = sha512.New

var algorithms = map[string]func() hash.Hash{
	"HS256": HS256,
	"HS512": HS512,
}

type jwtErrror struct {
	message string
}

func (jwtErr *jwtErrror) Error() string {
	return jwtErr.message
}

//Encode encodes a payload into a JWT token
func Encode(payload interface{}, secret string, algorithm string) (string, error) {

	alg, hasAlg := algorithms[algorithm]

	if !hasAlg {
		return "", &jwtErrror{"Invalid JWT token provided. Unable to parse it"}
	}

	headers := map[string]string {"typ": tokenType, "alg": algorithm}

	headersJSON, jsonError := json.Marshal(headers)

	if jsonError != nil {

		log.Fatalln("Error converting map to []byte: " + jsonError.Error())
	}

	payloadJSON, jsonError := json.Marshal(payload)

	if jsonError != nil {

		log.Fatalln("Error converting payload to []byte: " + jsonError.Error())
	}

	signingInput := strings.ReplaceAll(base64.URLEncoding.EncodeToString(headersJSON), "=", "") + "." + strings.ReplaceAll(base64.URLEncoding.EncodeToString(payloadJSON), "=", "")
	
	signature := hmacSign([]byte(signingInput), alg, secret)

	return strings.ReplaceAll(strings.Join([]string{signingInput, signature}, "."), "=", ""), nil

}

//Decode decodes a JWT token into a payload. The jwt token needs to necessarily have been initiate by 
//this library so that it contains the same header and body expected by this library to control validity
func Decode(jwtToken string, secret string, payload interface{}) error {

	if jwtToken == "" || strings.Count(jwtToken, ".") != 2 {
		return &jwtErrror{"Invalid JWT token provided. Empty or missing parts"}
	}

	parts := rSplit(jwtToken, ".", 1)

	if len(parts) != 2 {
		return &jwtErrror{"Invalid JWT token provided. Missing parts"}
	}

	signingInput, cryptoSegment := parts[0], parts[1]

	parts = strings.Split(signingInput, ".")

	if len(parts) != 2 {
		return &jwtErrror{"Invalid JWT token provided. Signing input missing parts"}
	}

	headerSegment, payloadSegment := parts[0], parts[1]
	headerData, err := base64.URLEncoding.DecodeString(addPlusSignsToBase64(headerSegment))

	if err != nil {
		return &jwtErrror{"Invalid JWT token provided. Unable to load header data: " + err.Error()}
	}

	var header map[string]string
	err = json.Unmarshal(headerData, &header)

	if err != nil {
		return &jwtErrror{"Invalid JWT token provided. Unable to unmarshal header: " + err.Error()}
	}

	payloadData, err := base64.URLEncoding.DecodeString(addPlusSignsToBase64(payloadSegment))

	if err != nil {
		return &jwtErrror{"Invalid JWT token provided. Unable to load payload data: " + err.Error()}
	}

	err = json.Unmarshal(payloadData, &payload)

	if err != nil {
		return &jwtErrror{"Invalid JWT token provided. Unable to unmarshal payload: " + err.Error()}
	}

	signature, err := base64.URLEncoding.DecodeString(addPlusSignsToBase64(cryptoSegment))

	if err != nil {
		return &jwtErrror{"Invalid JWT token provided. Unable to load signature data: " + err.Error() + "===> crypto segment=" + cryptoSegment}
	}

	err = verifySignature(signingInput, signature, header["alg"], secret)

	return err

}

func verifySignature(signingInput string, signature []byte, algName string, secret string) error {

	alg, hasAlg := algorithms[algName]

	if !hasAlg {

		return &jwtErrror{"Invalid JWT token provided. Unable to parse it"}

	}

	mac := hmac.New(alg, []byte(secret))
	mac.Write([]byte(signingInput))

	expectedMac := mac.Sum(nil)

	if !hmac.Equal(signature, expectedMac) {
		return &jwtErrror{"Invalid JWT token provided. Signatures don't match"}
	}

	return nil
}

func hmacSign(signingBytes []byte, alg func() hash.Hash, secret string) string {

	mac := hmac.New(alg, []byte(secret))
	mac.Write(signingBytes)

	output := mac.Sum(nil)

	return base64.URLEncoding.EncodeToString(output)
}

func rSplit(s string, sep string, n int) []string {
	parts := strings.Split(s, sep)

	if len(parts) > 1 && n > 0 {

		if n >= len(parts)-1 {
			return parts
		}

		var result []string

		added := 0

		tempStr := ""

		for i, part := range parts {

			if (i-1) < n {
				if tempStr == "" {

					tempStr = part

				} else {
					tempStr = tempStr + sep + part
				}

			} else {

				if added == 0 {
					result = append(result, tempStr)
					result = append(result, part)
				} else {
					result = append(result, part)

				}
				
				added++

			}
		}

		return result

	}

	return []string{s}
}

func addPlusSignsToBase64(data string) string {
	rem := len(data) % 4

	if rem > 0 {
		for i := 0; i< (4-rem); i++ {
			data = data + "="
		}
	}

	return data
}