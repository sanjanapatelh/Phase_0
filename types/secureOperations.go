package types

// SecureRequest wraps a regular Request with encryption and authentication
type SecureRequest struct {
	MessageEncrypted []byte `json:"message_encrypted"` // Encrypted Request
	Signature        []byte `json:"signature"`         // Message signature
	TimeOfDay        []byte `json:"time_of_day"`       // For preventing replay attacks
}

// SecureResponse wraps a regular Response with encryption and authentication
type SecureResponse struct {
	MessageEncrypted []byte `json:"message_encrypted"` // Encrypted Response
	Signature        []byte `json:"signature"`         // Message signature
	TimeOfDay        []byte `json:"time_of_day"`       // For preventing replay attacks
}