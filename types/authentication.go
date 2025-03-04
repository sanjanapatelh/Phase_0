package types

import (
	"crypto/rsa"
	"time"
)

// Communication message types
type MessageClientToServer struct {
	Name               string `json:"name"`
	SharedKeyEncrypted []byte `json:"shared_key_encrypted"`
	MessageEncrypted   []byte `json:"message_encrypted"`
}

type MessageServerToClient struct {
	Name             string `json:"name"`
	MessageEncrypted []byte `json:"message_encrypted"`
}

type ClientToServerEncryptedContents struct {
	Name                  string `json:"name"`
	Uid                   string `json:"uid"`
	Op                    string `json:"op"`
	ClientVerificationKey []byte `json:"client_public_key"`
	TimeOfDay             []byte `json:"time_of_day"`
	Signature             []byte `json:"signature"`
}

type ServerToClientEncryptedContents struct {
	Name                  string `json:"name"`
	Uid                   string `json:"uid"`
	Op                    string `json:"op"`
	ServerVerificationKey []byte `json:"client_public_key"`
	TimeOfDay             []byte `json:"time_of_day"`
	Signature             []byte `json:"signature"`
}

// Binding table data structure
type BindingTableData struct {
	ClientVerificationKey *rsa.PublicKey
	RecentLoginTime       time.Time
}

// Session information structure
type SessionInfo struct {
	SharedKey            []byte
	SigningKey           *rsa.PrivateKey
	VerificationKey      []byte
	Established          bool
	StartTime            time.Time
	User                 string
}

type SecurePayload struct {
    EncryptedData []byte `json:"encrypted_data"`
}