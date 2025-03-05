package types

import (
	"crypto/rsa"
	"time"
)

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
	ClientVerificationKey []byte `json:"public_key"`
	TimeOfDay             []byte `json:"time_of_day"`
	Signature             []byte `json:"signature"`
}

type ServerToClientEncryptedContents struct {
	Name                  string `json:"name"`
	Uid                   string `json:"uid"`
	Op                    string `json:"op"`
	ServerVerificationKey []byte `json:"public_key"`
	TimeOfDay             []byte `json:"time_of_day"`
	Signature             []byte `json:"signature"`
}

// Binding table data structure
type BindingTableData struct {
	ClientVerificationKey *rsa.PublicKey
	RecentLoginTime       time.Time
}