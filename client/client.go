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
	session = &auth_utils.SessionData{
		Active:    false,
		Name:      name,
	}
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
	response := &Response{Status: FAIL}
	if validateRequest(request) {
		switch request.Op {
		case LOGIN:
			doLogin(request, response)
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
		fmt.Println("Failed to generate session key")
		return
	}
	sharedKeyEncrypted := crypto_utils.EncryptPK(sharedKey, serverPublicKey)

	// 2. Generate a new signing key for this session
	clientSigningKey := crypto_utils.NewPrivateKey()
	clientVerificationKey := crypto_utils.PublicKeyToBytes(&clientSigningKey.PublicKey)

	// 3. Create the authentication message using our auth utility
	opString := string(rune(request.Op))
	authMessage := auth_utils.CreateAuthMessage(
		name, 
		request.Uid, 
		opString, 
		clientVerificationKey, 
		clientSigningKey,
	)

	// 4. Marshal and encrypt the auth message
	authMessageBytes, err := json.Marshal(authMessage)
	if err != nil {
		fmt.Println("Failed to marshal auth message:", err)
		return
	}
	
	// 5. Create the auth request to send to server
	authRequest := AuthRequest{
		SharedKeyEncrypted: sharedKeyEncrypted,
		MessageEncrypted:   crypto_utils.EncryptSK(authMessageBytes, sharedKey),
	}

	// 6. Marshal the auth request
	authRequestBytes, err := json.Marshal(authRequest)
	if err != nil {
		fmt.Println("Failed to marshal auth request:", err)
		return
	}

	// 7. Send auth request and receive response
	networkData := sendAndReceive(NetworkData{Payload: authRequestBytes, Name: name})

	// 8. Parse auth response
	var authResponse AuthResponse
	if err := json.Unmarshal(networkData.Payload, &authResponse); err != nil {
		fmt.Println("Failed to unmarshal auth response:", err)
		response.Status = FAIL
		return
	}

	// 9. Decrypt the response
	decryptedBytes, err := crypto_utils.DecryptSK(authResponse.MessageEncrypted, sharedKey)
	if err != nil {
		fmt.Println("Failed to decrypt server message:", err)
		response.Status = FAIL
		return
	}
	
	// 10. Parse server auth message
	var serverAuthMessage AuthMessage
	if err := json.Unmarshal(decryptedBytes, &serverAuthMessage); err != nil {
		fmt.Println("Failed to unmarshal server auth message:", err)
		response.Status = FAIL
		return
	}

	// 11. Verify server's identity and signature
	valid, err, serverVerificationKey := auth_utils.VerifyAuthMessage(serverAuthMessage, "", request.Uid)
	
	if err != nil {
		fmt.Println("Error verifying server message:", err)
		response.Status = FAIL
		return
	}
	
	// 12. Check server name matches
	namesMatch := strings.EqualFold(serverAuthMessage.Name, networkData.Name)
	
	if !valid || !namesMatch {
		fmt.Println("Server verification failed")
		response.Status = FAIL
		return
	}
	
	// 13. Store session data for subsequent requests
	session.Active = true
	session.SharedKey = sharedKey
	session.SigningKey = clientSigningKey
	session.VerificationKey = serverVerificationKey
	session.UserID = request.Uid
	session.PeerName = serverAuthMessage.Name
	
	// Login successful
	response.Status = OK
	response.Uid = request.Uid
	fmt.Println("Login succeeded! All verifications passed.")
}

func doSecureOp(request *Request, response *Response) {
	// 1. Create secure request
	secureRequest, err := auth_utils.EncryptRequest(request, session)
	if err != nil {
		fmt.Println("Failed to encrypt request:", err)
		response.Status = FAIL
		return
	}
	
	// 2. Marshal secure request
	secureRequestBytes, err := json.Marshal(secureRequest)
	if err != nil {
		fmt.Println("Failed to marshal secure request:", err)
		response.Status = FAIL
		return
	}
	
	// 3. Send secure request and receive secure response
	networkData := sendAndReceive(NetworkData{Payload: secureRequestBytes, Name: name})
	
	// 4. Parse secure response
	var secureResponse SecureResponse
	if err := json.Unmarshal(networkData.Payload, &secureResponse); err != nil {
		fmt.Println("Failed to unmarshal secure response:", err)
		response.Status = FAIL
		return
	}
	
	// 5. Decrypt and verify secure response
	decryptedResponse, valid, err := auth_utils.DecryptResponse(&secureResponse, session)
	if err != nil {
		fmt.Println("Failed to decrypt response:", err)
		response.Status = FAIL
		return
	}
	
	if !valid {
		fmt.Println("Response verification failed")
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
	}
}

func sendAndReceive(toSend NetworkData) NetworkData {
	Requests <- toSend
	return <-Responses
}