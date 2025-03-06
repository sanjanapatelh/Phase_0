package auth_utils

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"time"

	"crypto_utils"
	. "types"
)

// Session data for client and server
type SessionData struct {
	SharedKey         []byte            // Shared session key
	SigningKey        *rsa.PrivateKey   // Private signing key
	VerificationKey   *rsa.PublicKey    // Public verification key of the other party
	UserID            string            // Current user ID
	Active            bool              // Is session active
	Name              string            // Local party name
	PeerName          string            // Other party name
}

// CreateAuthMessage builds a properly signed authentication message
func CreateAuthMessage(name string, uid string, op string, verificationKey []byte, signingKey *rsa.PrivateKey) AuthMessage {
	// Create time of day
	currentTOD := crypto_utils.ReadClock()
	timeOfDay := crypto_utils.TodToBytes(currentTOD)

	// Build the signing message with all required components
	signingMessage := []byte(name + uid + op)
	signingMessage = append(signingMessage, timeOfDay...)
	signingMessage = append(signingMessage, verificationKey...)

	// Sign the message
	signature := crypto_utils.Sign(signingMessage, signingKey)

	// Create the complete auth message
	return AuthMessage{
		Name:            name,
		Uid:             uid,
		Op:              op,
		VerificationKey: verificationKey,
		TimeOfDay:       timeOfDay,
		Signature:       signature,
	}
}

// VerifyAuthMessage checks the signature, time, name and UID of an auth message
func VerifyAuthMessage(message AuthMessage, expectedName string, expectedUID string) (bool, error, *rsa.PublicKey) {
	// Parse verification key
	verificationKey, err := crypto_utils.BytesToPublicKey(message.VerificationKey)
	if err != nil {
		return false, err, nil
	}

	// Rebuild signing message for verification
	signingMessage := []byte(message.Name + message.Uid + message.Op)
	signingMessage = append(signingMessage, message.TimeOfDay...)
	signingMessage = append(signingMessage, message.VerificationKey...)

	// Verify time - not too far in future or past (5 min threshold)
	messageTOD := crypto_utils.BytesToTod(message.TimeOfDay)
	currentTOD := crypto_utils.ReadClock()
	
	validTime := !messageTOD.After(currentTOD.Add(5*time.Minute)) && 
		!messageTOD.Before(currentTOD.Add(-5*time.Minute))
	
	// Verify signature
	validSignature := crypto_utils.Verify(
		message.Signature,
		crypto_utils.Hash(signingMessage),
		verificationKey,
	)
	
	// Verify name and UID match expected values if provided
	validName := message.Name == expectedName || expectedName == ""
	validUID := message.Uid == expectedUID || expectedUID == ""
	
	return validSignature && validTime && validName && validUID, nil, verificationKey
}

// EncryptRequest securely encrypts a request
func EncryptRequest(request *Request, session *SessionData) (*SecureRequest, error) {
	if !session.Active {
		return nil, errors.New("session not active")
	}
	
	// Marshal the request
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	
	// Encrypt the request with shared key
	encryptedRequest := crypto_utils.EncryptSK(requestBytes, session.SharedKey)
	
	// Create time of day for replay protection
	currentTOD := crypto_utils.ReadClock()
	timeOfDay := crypto_utils.TodToBytes(currentTOD)
	
	// Create signature (Hash(encrypted_request + time_of_day))
	signingMessage := append(encryptedRequest, timeOfDay...)
	signature := crypto_utils.Sign(
		crypto_utils.Hash(signingMessage),
		session.SigningKey,
	)
	
	// Return secure request
	return &SecureRequest{
		MessageEncrypted: encryptedRequest,
		TimeOfDay:        timeOfDay,
		Signature:        signature,
	}, nil
}

// DecryptRequest securely decrypts and verifies a request
func DecryptRequest(secureRequest *SecureRequest, session *SessionData) (*Request, bool, error) {
	if !session.Active {
		return nil, false, errors.New("session not active")
	}
	
	// Verify time of day
	requestTOD := crypto_utils.BytesToTod(secureRequest.TimeOfDay)
	currentTOD := crypto_utils.ReadClock()
	
	validTime := !requestTOD.After(currentTOD.Add(5*time.Minute)) && 
		!requestTOD.Before(currentTOD.Add(-5*time.Minute))
	
	if !validTime {
		return nil, false, errors.New("invalid timestamp")
	}
	
	// Verify signature
	signingMessage := append(secureRequest.MessageEncrypted, secureRequest.TimeOfDay...)
	validSignature := crypto_utils.Verify(
		secureRequest.Signature,
		crypto_utils.Hash(signingMessage),
		session.VerificationKey,
	)
	
	if !validSignature {
		return nil, false, errors.New("invalid signature")
	}
	
	// Decrypt request
	decryptedBytes, err := crypto_utils.DecryptSK(secureRequest.MessageEncrypted, session.SharedKey)
	if err != nil {
		return nil, false, err
	}
	
	// Unmarshal request
	var request Request
	if err := json.Unmarshal(decryptedBytes, &request); err != nil {
		return nil, false, err
	}
	
	return &request, true, nil
}

// EncryptResponse securely encrypts a response
func EncryptResponse(response *Response, session *SessionData) (*SecureResponse, error) {
	if !session.Active {
		return nil, errors.New("session not active")
	}
	
	// Marshal the response
	responseBytes, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	
	// Encrypt the response with shared key
	encryptedResponse := crypto_utils.EncryptSK(responseBytes, session.SharedKey)
	
	// Create time of day for replay protection
	currentTOD := crypto_utils.ReadClock()
	timeOfDay := crypto_utils.TodToBytes(currentTOD)
	
	// Create signature (Hash(encrypted_response + time_of_day))
	signingMessage := append(encryptedResponse, timeOfDay...)
	signature := crypto_utils.Sign(
		crypto_utils.Hash(signingMessage),
		session.SigningKey,
	)
	
	// Return secure response
	return &SecureResponse{
		MessageEncrypted: encryptedResponse,
		TimeOfDay:        timeOfDay,
		Signature:        signature,
	}, nil
}

// DecryptResponse securely decrypts and verifies a response
func DecryptResponse(secureResponse *SecureResponse, session *SessionData) (*Response, bool, error) {
	if !session.Active {
		return nil, false, errors.New("session not active")
	}
	
	// Verify time of day
	responseTOD := crypto_utils.BytesToTod(secureResponse.TimeOfDay)
	currentTOD := crypto_utils.ReadClock()
	
	validTime := !responseTOD.After(currentTOD.Add(5*time.Minute)) && 
		!responseTOD.Before(currentTOD.Add(-5*time.Minute))
	
	if !validTime {
		return nil, false, errors.New("invalid timestamp")
	}
	
	// Verify signature
	signingMessage := append(secureResponse.MessageEncrypted, secureResponse.TimeOfDay...)
	validSignature := crypto_utils.Verify(
		secureResponse.Signature,
		crypto_utils.Hash(signingMessage),
		session.VerificationKey,
	)
	
	if !validSignature {
		return nil, false, errors.New("invalid signature")
	}
	
	// Decrypt response
	decryptedBytes, err := crypto_utils.DecryptSK(secureResponse.MessageEncrypted, session.SharedKey)
	if err != nil {
		return nil, false, err
	}
	
	// Unmarshal response
	var response Response
	if err := json.Unmarshal(decryptedBytes, &response); err != nil {
		return nil, false, err
	}
	
	return &response, true, nil
}