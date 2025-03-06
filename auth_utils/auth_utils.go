package auth_utils

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"

	"crypto_utils"
	. "types"
)

// Simple global map for tracking authentication nonces
var AuthNonceMap = make(map[string]bool)

// Session data for client and server
type SessionData struct {
	SharedKey       []byte                // Shared session key
	SigningKey      *rsa.PrivateKey       // Private signing key
	VerificationKey *rsa.PublicKey        // Public verification key of the other party
	UserID          string                // Current user ID
	Active          bool                  // Is session active
	Name            string                // Local party name
	SeenNonces      map[string]bool       // map to track used nonces
}

// Initialize session data
func InitSessionData(name string, signingKey *rsa.PrivateKey) *SessionData {
	return &SessionData{
		Active:     false,
		Name:       name,
		SigningKey: signingKey,
		SeenNonces: make(map[string]bool),
	}
}

// Check if a nonce has been seen before in a session and record it if not
// Returns true if the nonce is new, false if it's been seen before
func checkAndRecordNonce(session *SessionData, nonce []byte) bool {
	// Convert nonce to hex string for map key
	nonceStr := fmt.Sprintf("%x", nonce)
	
	// Check if this nonce has been seen before
	if session.SeenNonces[nonceStr] {
		return false // Nonce has been seen before
	}
	
	// Record this nonce
	session.SeenNonces[nonceStr] = true
	
	return true // Nonce is new
}

// Check if an authentication nonce has been seen before
// This is used during the login process before a session is established
func CheckAndRecordAuthNonce(nonce []byte) bool {
	// Convert nonce to hex string for map key
	nonceStr := fmt.Sprintf("%x", nonce)
	
	// Check if this nonce has been seen before
	if AuthNonceMap[nonceStr] {
		return false // Nonce has been seen before
	}
	
	// Record this nonce
	AuthNonceMap[nonceStr] = true
	
	return true // Nonce is new
}

// CreateAuthMessage builds a properly structured authentication message
func CreateAuthMessage(name string, uid string, op string, verificationKey []byte, signingKey *rsa.PrivateKey) ([]byte, error) {
	// Create time of day
	currentTOD := crypto_utils.ReadClock()
	timeOfDay := crypto_utils.TodToBytes(currentTOD)
	
	// Generate nonce
	nonce := crypto_utils.RandomBytes(4)
	
	// Create the inner auth message
	innerAuthMessage := InnerAuthMessage{
		Name:            name,
		Uid:             uid,
		Op:              op,
		VerificationKey: verificationKey,
		TimeOfDay:       timeOfDay,
		Nonce:           nonce,
	}
	
	// Serialize the inner message
	innerMessageBytes, err := json.Marshal(innerAuthMessage)
	if err != nil {
		return nil, err
	}
	
	// Sign the serialized inner message
	signature := crypto_utils.Sign(innerMessageBytes, signingKey)
	
	// Create the encrypted content
	authEncryptedContent := AuthEncryptedContent{
		InnerMessage: innerMessageBytes,
		Signature:    signature,
	}
	
	// Serialize the encrypted content
	return json.Marshal(authEncryptedContent)
}

// EncryptAuthMessage encrypts an auth message with the provided shared key
func EncryptAuthMessage(contentBytes []byte, sharedKey []byte) []byte {
	return crypto_utils.EncryptSK(contentBytes, sharedKey)
}

// VerifyAndDecryptAuthMessage verifies and extracts an auth message
func VerifyAndDecryptAuthMessage(encryptedBytes []byte, sharedKey []byte, verificationKey *rsa.PublicKey, 
	expectedName string, expectedUID string) (*InnerAuthMessage, bool, error) {
	
	// Decrypt the message
	decryptedBytes, err := crypto_utils.DecryptSK(encryptedBytes, sharedKey)
	if err != nil {
		return nil, false, err
	}
	
	// Unmarshal the encrypted content
	var encryptedContent AuthEncryptedContent
	if err := json.Unmarshal(decryptedBytes, &encryptedContent); err != nil {
		return nil, false, err
	}
	
	// Verify signature
	validSignature := crypto_utils.Verify(
		encryptedContent.Signature,
		crypto_utils.Hash(encryptedContent.InnerMessage),
		verificationKey,
	)
	
	if !validSignature {
		return nil, false, errors.New("invalid signature")
	}
	
	// Unmarshal the inner message
	var innerMessage InnerAuthMessage
	if err := json.Unmarshal(encryptedContent.InnerMessage, &innerMessage); err != nil {
		return nil, false, err
	}
	
	// Verify name if provided
	validName := innerMessage.Name == expectedName || expectedName == ""
	if !validName {
		return nil, false, errors.New("name mismatch")
	}
	
	// Verify uid if provided
	validUID := innerMessage.Uid == expectedUID || expectedUID == ""
	if !validUID {
		return nil, false, errors.New("uid mismatch")
	}
	
	// Check if nonce has been seen before
	if !CheckAndRecordAuthNonce(innerMessage.Nonce) {
		return nil, false, errors.New("replay attack detected: repeated nonce")
	}
	
	return &innerMessage, true, nil
}

// EncryptRequest securely encrypts a request
func EncryptRequest(request *Request, session *SessionData) (*SecureMessage, error) {
	if !session.Active {
		return nil, errors.New("session not active")
	}
	
	// Marshal the request
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	
	// Generate a nonce for replay protection
	nonce := crypto_utils.RandomBytes(4)
	
	// Get current time of day
	currentTOD := crypto_utils.ReadClock()
	timeOfDay := crypto_utils.TodToBytes(currentTOD)
	
	// Create inner secure message
	innerMessage := InnerSecureMessage{
		Name:      session.Name,
		TimeOfDay: timeOfDay,
		Nonce:     nonce,
		Message:   requestBytes,
	}
	
	// Marshal the inner message
	innerMessageBytes, err := json.Marshal(innerMessage)
	if err != nil {
		return nil, err
	}
	
	// Sign the inner message
	signature := crypto_utils.Sign(innerMessageBytes, session.SigningKey)
	
	// Create the content to be encrypted
	encryptedContent := EncryptedContent{
		InnerMessage: innerMessageBytes,
		Signature:    signature,
	}
	
	// Marshal the content
	contentBytes, err := json.Marshal(encryptedContent)
	if err != nil {
		return nil, err
	}
	
	// Encrypt everything with shared key
	encryptedData := crypto_utils.EncryptSK(contentBytes, session.SharedKey)
	
	// Return secure message
	return &SecureMessage{
		EncryptedData: encryptedData,
	}, nil
}

// DecryptRequest securely decrypts and verifies a request
func DecryptRequest(secureMessage *SecureMessage, session *SessionData) (*Request, bool, error) {
	if !session.Active {
		return nil, false, errors.New("session not active")
	}
	
	// Decrypt the encrypted data
	decryptedContentBytes, err := crypto_utils.DecryptSK(secureMessage.EncryptedData, session.SharedKey)
	if err != nil {
		return nil, false, err
	}
	
	// Unmarshal the encrypted content
	var encryptedContent EncryptedContent
	if err := json.Unmarshal(decryptedContentBytes, &encryptedContent); err != nil {
		return nil, false, err
	}
	
	// Verify signature of inner message
	validSignature := crypto_utils.Verify(
		encryptedContent.Signature,
		crypto_utils.Hash(encryptedContent.InnerMessage),
		session.VerificationKey,
	)
	
	if !validSignature {
		return nil, false, errors.New("invalid signature")
	}
	
	// Unmarshal the inner message
	var innerMessage InnerSecureMessage
	if err := json.Unmarshal(encryptedContent.InnerMessage, &innerMessage); err != nil {
		return nil, false, err
	}
	
	// Check if nonce has been seen before
	if !checkAndRecordNonce(session, innerMessage.Nonce) {
		return nil, false, errors.New("replay attack detected: repeated nonce")
	}
	
	// Unmarshal the original request
	var request Request
	if err := json.Unmarshal(innerMessage.Message, &request); err != nil {
		return nil, false, err
	}
	
	return &request, true, nil
}

// EncryptResponse securely encrypts a response
func EncryptResponse(response *Response, session *SessionData) (*SecureMessage, error) {
	if !session.Active {
		return nil, errors.New("session not active")
	}
	
	// Marshal the response
	responseBytes, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	
	// Generate a nonce for replay protection
	nonce := crypto_utils.RandomBytes(4)
	
	// Get current time of day
	currentTOD := crypto_utils.ReadClock()
	timeOfDay := crypto_utils.TodToBytes(currentTOD)
	
	// Create inner secure message
	innerMessage := InnerSecureMessage{
		Name:      session.Name,
		TimeOfDay: timeOfDay,
		Nonce:     nonce,
		Message:   responseBytes,
	}
	
	// Marshal the inner message
	innerMessageBytes, err := json.Marshal(innerMessage)
	if err != nil {
		return nil, err
	}
	
	// Sign the inner message
	signature := crypto_utils.Sign(innerMessageBytes, session.SigningKey)
	
	// Create the content to be encrypted
	encryptedContent := EncryptedContent{
		InnerMessage: innerMessageBytes,
		Signature:    signature,
	}
	
	// Marshal the content
	contentBytes, err := json.Marshal(encryptedContent)
	if err != nil {
		return nil, err
	}
	
	// Encrypt everything with shared key
	encryptedData := crypto_utils.EncryptSK(contentBytes, session.SharedKey)
	
	// Return secure message
	return &SecureMessage{
		EncryptedData: encryptedData,
	}, nil
}

// DecryptResponse securely decrypts and verifies a response
func DecryptResponse(secureMessage *SecureMessage, session *SessionData) (*Response, bool, error) {
	if !session.Active {
		return nil, false, errors.New("session not active")
	}
	
	// Decrypt the encrypted data
	decryptedContentBytes, err := crypto_utils.DecryptSK(secureMessage.EncryptedData, session.SharedKey)
	if err != nil {
		return nil, false, err
	}
	
	// Unmarshal the encrypted content
	var encryptedContent EncryptedContent
	if err := json.Unmarshal(decryptedContentBytes, &encryptedContent); err != nil {
		return nil, false, err
	}
	
	// Verify signature of inner message
	validSignature := crypto_utils.Verify(
		encryptedContent.Signature,
		crypto_utils.Hash(encryptedContent.InnerMessage),
		session.VerificationKey,
	)
	
	if !validSignature {
		return nil, false, errors.New("invalid signature")
	}
	
	// Unmarshal the inner message
	var innerMessage InnerSecureMessage
	if err := json.Unmarshal(encryptedContent.InnerMessage, &innerMessage); err != nil {
		return nil, false, err
	}
	
	// Check if nonce has been seen before
	if !checkAndRecordNonce(session, innerMessage.Nonce) {
		return nil, false, errors.New("replay attack detected: repeated nonce")
	}
	
	// Unmarshal the original response
	var response Response
	if err := json.Unmarshal(innerMessage.Message, &response); err != nil {
		return nil, false, err
	}
	
	return &response, true, nil
}