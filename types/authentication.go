package types

import (
	"crypto/rsa"
	"time"
)

// InnerAuthMessage is the inner structure containing all authentication data
type InnerAuthMessage struct {
    Name           string `json:"name"`
    Uid            string `json:"uid"`
    Op     string `json:"operation"`
    TimeOfDay      []byte `json:"timeOfDay"`
    VerificationKey []byte `json:"verificationKey"`
    Nonce          string `json:"nonce"`
    Password       string `json:"password"` // Make sure this is properly defined
    Status         string `json:"status,omitempty"`
}

// AuthEncryptedContent contains the inner message and its signature
type AuthEncryptedContent struct {
	InnerMessage []byte `json:"inner_message"` // Serialized InnerAuthMessage
	Signature    []byte `json:"signature"`     // Signature of the InnerAuthMessage
}

// Existing types - keep these for compatibility
type AuthRequest struct {
	SharedKeyEncrypted []byte `json:"shared_key_encrypted"`
	MessageEncrypted   []byte `json:"message_encrypted"`
}

type AuthResponse struct {
	MessageEncrypted []byte `json:"message_encrypted"`
}

// Binding table data structure
type BindingTableData struct {
	ClientVerificationKey *rsa.PublicKey
	RecentLoginTime       time.Time
	PasswordHash          []byte
	Salt                  []byte 
}

