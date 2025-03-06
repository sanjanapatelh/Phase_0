package types

// SecureMessage contains the encrypted inner message and signature
type SecureMessage struct {
	EncryptedData []byte `json:"encrypted_data"` // Encrypted(inner message + signature)
}

// EncryptedContent is what gets encrypted in the SecureMessage
type EncryptedContent struct {
	InnerMessage []byte `json:"inner_message"` // Serialized InnerSecureMessage
	Signature    []byte `json:"signature"`     // Signature of the InnerSecureMessage
}

// InnerSecureMessage contains all the data needed for secure communication
type InnerSecureMessage struct {
	Name       string      `json:"name"`        // Name of the sender
	TimeOfDay  []byte      `json:"time_of_day"` // Timestamp for freshness check
	Nonce      []byte      `json:"nonce"`       // For replay protection
	Message    []byte      `json:"message"`     // Original request/response JSON
}