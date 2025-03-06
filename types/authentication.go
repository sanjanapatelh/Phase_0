package types

import (
	"crypto/rsa"
	"time"
)

// Authentication related types
type AuthRequest struct {
	SharedKeyEncrypted []byte `json:"shared_key_encrypted"`
	MessageEncrypted   []byte `json:"message_encrypted"`
}

type AuthResponse struct {
	MessageEncrypted   []byte `json:"message_encrypted"`
}

type AuthMessage struct {
	Name            string `json:"name"`
	Uid             string `json:"uid"`
	Op              string `json:"op"`
	VerificationKey []byte `json:"verification_key"` // Renamed from public_key for consistency
	TimeOfDay       []byte `json:"time_of_day"`
	Signature       []byte `json:"signature"`
}

// Server response type
type MessageServerToClient struct {
	Name             string `json:"name"`
	MessageEncrypted []byte `json:"message_encrypted"`
}

// Binding table data structure
type BindingTableData struct {
	ClientVerificationKey *rsa.PublicKey
	RecentLoginTime       time.Time
}