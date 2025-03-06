package client

import (
	"crypto/rsa"
	"encoding/json"
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
			if !session.Active{
				doLogin(request, response)
			}
		case LOGOUT, CREATE, DELETE, READ, WRITE, COPY:
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
	authContentBytes, err := auth_utils.CreateAuthMessage(
		name, 
		request.Uid, 
		opString, 
		clientVerificationKey, 
		clientSigningKey,
	)
	
	if err != nil {
		response.Status = FAIL
		return
	}
	
	// 4. Encrypt the auth content with shared key
	encryptedAuthBytes := auth_utils.EncryptAuthMessage(authContentBytes, sharedKey)
	
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