package client

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"

	"auth_utils"
	"crypto_utils"
	. "types"
)

var name string
var Requests chan NetworkData
var Responses chan NetworkData
var serverPublicKey *rsa.PublicKey

// Session data for the client
var session *auth_utils.SessionData

func init() {
	name = uuid.NewString()
	Requests = make(chan NetworkData)
	Responses = make(chan NetworkData)

	// Initialize session data
	session = auth_utils.InitSessionData(name, nil)
}

func ObtainServerPublicKey() {
	serverPublicKeyBytes, err := os.ReadFile("SERVER_PUBLICKEY")
	if err != nil {
		panic(err)
	}
	serverPublicKey, err = crypto_utils.BytesToPublicKey(serverPublicKeyBytes)
	if err != nil {
		panic(err)
	}
}

func ProcessOp(request *Request) *Response {
	response := &Response{Status: FAIL, Uid: session.UserID}
	if validateRequest(request) {
		switch request.Op {
		case LOGIN:
			if !session.Active {
				doLogin(request, response)
			}
		case LOGOUT, CREATE, DELETE, READ, WRITE, COPY, CHANGE_PASS:
			fmt.Println(request.Op)
			if session.Active {
				doSecureOp(request, response)
			}
		case REGISTER:
			doRegister(request, response)
		case MODACL, REVACL:
			if session.Active {
				doSecureOp(request, response)
			}
		default:
			// struct already default initialized to FAIL status
		}
	}
	return response
}

func validateRequest(r *Request) bool {
	fmt.Println(r.Op)
	// Restrict request without UID
	switch r.Op {
	case CREATE, WRITE:
		return r.Key != "" && r.Val != nil
	case DELETE, READ:
		return r.Key != ""
	case COPY:
		return r.Src_key != "" && r.Dst_key != ""
	case LOGIN:
		return r.Uid != ""
	case LOGOUT:
		return true
	case REGISTER:
		return r.Uid != "" && r.Pass != ""
	case CHANGE_PASS:
		return r.Old_pass != "" && r.New_pass != ""
	case MODACL, REVACL:
		return r.Key != ""
	default:
		return false
	}
}

func doLogin(request *Request, response *Response) {
	// 1. Generate and encrypt shared key using server's public key
	sharedKey := crypto_utils.NewSessionKey()
	if sharedKey == nil {
		response.Status = FAIL
		return
	}
	sharedKeyEncrypted := crypto_utils.EncryptPK(sharedKey, serverPublicKey)

	// 2. Generate a new signing key for this session
	clientSigningKey := crypto_utils.NewPrivateKey()
	clientVerificationKey := crypto_utils.PublicKeyToBytes(&clientSigningKey.PublicKey)

	// 3. Create the authentication message
	opString := string(rune(request.Op))

	// Include the password in the auth message
	innerAuthMessage := InnerAuthMessage{
		Name:            name,
		Uid:             request.Uid,
		Op:              opString,
		Password:        request.Pass,
		VerificationKey: clientVerificationKey,
		TimeOfDay:       crypto_utils.TodToBytes(crypto_utils.ReadClock()),
		Nonce:           fmt.Sprintf("%x", crypto_utils.RandomBytes(4)),
	}

	innerMessageBytes, err := json.Marshal(innerAuthMessage)
	if err != nil {
		response.Status = FAIL
		return
	}

	// Sign the inner message
	signature := crypto_utils.Sign(innerMessageBytes, clientSigningKey)

	// Create the auth encrypted content
	authEncryptedContent := AuthEncryptedContent{
		InnerMessage: innerMessageBytes,
		Signature:    signature,
	}

	authContentBytes, err := json.Marshal(authEncryptedContent)
	if err != nil {
		response.Status = FAIL
		return
	}

	// 4. Encrypt the auth content with shared key
	encryptedAuthBytes := crypto_utils.EncryptSK(authContentBytes, sharedKey)

	// 5. Create the auth request to send to server
	authRequest := AuthRequest{
		SharedKeyEncrypted: sharedKeyEncrypted,
		MessageEncrypted:   encryptedAuthBytes,
	}

	// 6. Marshal the auth request
	authRequestBytes, err := json.Marshal(authRequest)
	if err != nil {
		response.Status = FAIL
		return
	}

	// 7. Send auth request and receive response
	networkData := sendAndReceive(NetworkData{Payload: authRequestBytes, Name: name})

	// 8. Parse auth response
	var authResponse AuthResponse
	if err := json.Unmarshal(networkData.Payload, &authResponse); err != nil {
		response.Status = FAIL
		return
	}

	// IMPORTANT: Add validation check for empty encrypted message
	if len(authResponse.MessageEncrypted) < 12 { // Need at least 12 bytes for the IV
		response.Status = FAIL
		return
	}

	// 9. Verify server public key
	serverVerificationKey, err := crypto_utils.BytesToPublicKey(crypto_utils.PublicKeyToBytes(serverPublicKey))
	if err != nil {
		response.Status = FAIL
		return
	}

	// 10. Verify and decrypt the server's response
	innerServerMessage, valid, err := auth_utils.VerifyAndDecryptAuthMessage(
		authResponse.MessageEncrypted,
		sharedKey,
		serverVerificationKey,
		"",
		request.Uid,
	)

	if err != nil {
		// Error already happened, don't try to continue
		response.Status = FAIL
		return
	}

	if !valid {
		response.Status = FAIL
		return
	}

	// 11. Check server name matches
	if !strings.EqualFold(innerServerMessage.Name, networkData.Name) {
		response.Status = FAIL
		return
	}

	// 12. Parse server verification key from inner message
	serverVerificationKey, err = crypto_utils.BytesToPublicKey(innerServerMessage.VerificationKey)
	if err != nil {
		response.Status = FAIL
		return
	}

	// 13. Store session data for subsequent requests
	session.Active = true
	session.SharedKey = sharedKey
	session.SigningKey = clientSigningKey
	session.VerificationKey = serverVerificationKey
	session.UserID = request.Uid

	// Login successful
	response.Status = OK
	response.Uid = request.Uid
}

func doRegister(request *Request, response *Response) {
	// 1. Generate and encrypt shared key using server's public key
	if session.Active {
		response.Status = FAIL
		return
	}
	sharedKey := crypto_utils.NewSessionKey()
	if sharedKey == nil {
		response.Status = FAIL
		return
	}
	sharedKeyEncrypted := crypto_utils.EncryptPK(sharedKey, serverPublicKey)

	// 2. Generate a new signing key for this session
	clientSigningKey := crypto_utils.NewPrivateKey()
	clientVerificationKey := crypto_utils.PublicKeyToBytes(&clientSigningKey.PublicKey)

	// 3. Create the authentication message with REGISTER operation
	opString := string(rune(REGISTER))

	// Create inner auth message with password
	innerAuthMessage := InnerAuthMessage{
		Name:            name,
		Uid:             request.Uid,
		Op:              opString,
		Password:        request.Pass, // Include password in the message
		VerificationKey: clientVerificationKey,
		TimeOfDay:       crypto_utils.TodToBytes(crypto_utils.ReadClock()),
		Nonce:           fmt.Sprintf("%x", crypto_utils.RandomBytes(4)),
	}

	// 4. Marshal the inner auth message
	innerMessageBytes, err := json.Marshal(innerAuthMessage)
	if err != nil {
		response.Status = FAIL
		return
	}

	// 5. Sign the serialized inner message
	signature := crypto_utils.Sign(innerMessageBytes, clientSigningKey)

	// 6. Create the encrypted content
	authEncryptedContent := AuthEncryptedContent{
		InnerMessage: innerMessageBytes,
		Signature:    signature,
	}

	// 7. Marshal the encrypted content
	authContentBytes, err := json.Marshal(authEncryptedContent)
	if err != nil {
		response.Status = FAIL
		return
	}

	// 8. Encrypt the auth content with the shared key
	encryptedAuthBytes := crypto_utils.EncryptSK(authContentBytes, sharedKey)

	// 9. Create the auth request
	authRequest := AuthRequest{
		SharedKeyEncrypted: sharedKeyEncrypted,
		MessageEncrypted:   encryptedAuthBytes,
	}

	// 10. Marshal the auth request
	authRequestBytes, err := json.Marshal(authRequest)
	if err != nil {
		response.Status = FAIL
		return
	}

	// 11. Send auth request and receive response
	networkData := sendAndReceive(NetworkData{Payload: authRequestBytes, Name: name})

	// 12. Parse response
	var regResponse Response
	if err := json.Unmarshal(networkData.Payload, &regResponse); err != nil {
		response.Status = FAIL
		return
	}

	// 13. Update response status and UID
	response.Status = regResponse.Status
	response.Uid = regResponse.Uid
}

func doChangePass(request *Request, response *Response) {
	// Check if session is active
	if !session.Active {
		response.Status = FAIL
		return
	}

	// Create a request for password change using the existing Request type
	// The Request already has Old_pass and New_pass fields we can use
	changePassRequest := &Request{
		Op:       CHANGE_PASS,
		Uid:      session.UserID,
		Old_pass: request.Old_pass,
		New_pass: request.New_pass,
	}

	// Use the existing doSecureOp function to handle the secure communication
	// This will encrypt the request with the session key and handle the response
	doSecureOp(changePassRequest, response)
}

func doSecureOp(request *Request, response *Response) {
	// 1. Create secure request
	secureMessage, err := auth_utils.EncryptRequest(request, session)
	if err != nil {
		response.Status = FAIL
		return
	}

	// 2. Marshal secure message
	secureMessageBytes, err := json.Marshal(secureMessage)
	if err != nil {
		response.Status = FAIL
		return
	}

	// 3. Send secure message and receive secure response
	networkData := sendAndReceive(NetworkData{Payload: secureMessageBytes, Name: name})

	// 4. Parse secure response
	var secureResponseMessage SecureMessage
	if err := json.Unmarshal(networkData.Payload, &secureResponseMessage); err != nil {
		response.Status = FAIL
		return
	}

	// 5. Decrypt and verify secure response
	decryptedResponse, valid, err := auth_utils.DecryptResponse(&secureResponseMessage, session)
	if err != nil {
		response.Status = FAIL
		return
	}

	if !valid {
		response.Status = FAIL
		return
	}

	// 6. Copy response data
	response.Status = decryptedResponse.Status
	response.Val = decryptedResponse.Val
	response.Uid = decryptedResponse.Uid

	// 7. Handle logout specially - clear session if logout was successful
	if request.Op == LOGOUT && response.Status == OK {
		session.Active = false
		session.SharedKey = nil
		session.UserID = ""
		// Clear nonce map on logout
		if session.SeenNonces != nil {
			session.SeenNonces = make(map[string]bool)
		}
	}
}

func sendAndReceive(toSend NetworkData) NetworkData {
	Requests <- toSend
	return <-Responses
}
