package types

import (
	"crypto/rsa"
	"time"
)

// InnerAuthMessage is the inner structure containing all authentication data
type InnerAuthMessage struct {
	Name            string `json:"name"`
	Uid             string `json:"uid"`
	Op              string `json:"op"`
	VerificationKey []byte `json:"verification_key"`
	TimeOfDay       []byte `json:"time_of_day"`
	Nonce           []byte `json:"nonce"`
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
}