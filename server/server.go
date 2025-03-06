package server

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/uuid"

	"auth_utils"
	"crypto_utils"
	. "types"
)

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey

var name string
var kvstore map[string]interface{}
var Requests chan NetworkData
var Responses chan NetworkData

// Session management
var session *auth_utils.SessionData
var BindingTable map[string]BindingTableData

func init() {
	privateKey = crypto_utils.NewPrivateKey()
	publicKey = &privateKey.PublicKey
	publicKeyBytes := crypto_utils.PublicKeyToBytes(publicKey)
	if err := os.WriteFile("SERVER_PUBLICKEY", publicKeyBytes, 0666); err != nil {
		panic(err)
	}

	name = uuid.NewString()
	kvstore = make(map[string]interface{})
	BindingTable = make(map[string]BindingTableData)
	Requests = make(chan NetworkData)
	Responses = make(chan NetworkData)
	
	// Initialize session
	session = &auth_utils.SessionData{
		Active:     false,
		Name:       name,
		SigningKey: privateKey,
	}

	go receiveThenSend()
}

func receiveThenSend() {
	defer close(Responses)

	for request := range Requests {
		Responses <- process(request)
	}
}

// Process incoming requests
func process(requestData NetworkData) NetworkData {
	var responseBytes []byte

	// First try to unmarshal as an AuthRequest (for login)
	var authRequest AuthRequest
	err := json.Unmarshal(requestData.Payload, &authRequest)
	
	if err == nil && len(authRequest.SharedKeyEncrypted) > 0 && len(authRequest.MessageEncrypted) > 0 {
		// This is an authentication request
		var response Response
		var authResponse AuthResponse
		
		processAuthLogin(&authRequest, requestData.Name, &response, &authResponse)
		
		responseBytes, _ = json.Marshal(authResponse)
		return NetworkData{Payload: responseBytes, Name: name}
	}
	
	// Check if it's a secure operation request
	if session.Active {
		var secureRequest SecureRequest
		if err := json.Unmarshal(requestData.Payload, &secureRequest); err == nil {
			// This is a secure request during an active session
			processSecureRequest(&secureRequest, requestData.Name, &responseBytes)
			return NetworkData{Payload: responseBytes, Name: name}
		}
	}
	
	// Not an auth request or secure request, try as a regular request
	var request Request
	var response Response
	
	if err := json.Unmarshal(requestData.Payload, &request); err != nil {
		response.Status = FAIL
		responseBytes, _ = json.Marshal(response)
		return NetworkData{Payload: responseBytes, Name: name}
	}
	
	// Regular operation
	doOp(&request, &response)
	
	responseBytes, _ = json.Marshal(response)
	return NetworkData{Payload: responseBytes, Name: name}
}

// Process a secure request during an active session
func processSecureRequest(secureRequest *SecureRequest, clientName string, responseBytes *[]byte) {
	// Default failure response
	response := Response{Status: FAIL, Uid: session.UserID}
	secureResponse, err := auth_utils.EncryptResponse(&response, session)
	if err != nil {
		secureResponseBytes, _ := json.Marshal(secureResponse)
		*responseBytes = secureResponseBytes
		return
	}
	
	// 1. Decrypt and verify the secure request
	request, valid, err := auth_utils.DecryptRequest(secureRequest, session)
	if err != nil || !valid {
		fmt.Println("Error processing secure request:", err)
		secureResponseBytes, _ := json.Marshal(secureResponse)
		*responseBytes = secureResponseBytes
		return
	}
	
	// 2. Process the regular operation
	doOp(request, &response)
	
	// 3. Encrypt the response
	secureResponse, err = auth_utils.EncryptResponse(&response, session)
	if err != nil {
		fmt.Println("Error encrypting response:", err)
		secureResponseBytes, _ := json.Marshal(secureResponse)
		*responseBytes = secureResponseBytes
		return
	}
	
	// 4. Marshal the secure response
	secureResponseBytes, _ := json.Marshal(secureResponse)
	*responseBytes = secureResponseBytes
	
	// 5. Special handling for logout
	if request.Op == LOGOUT && response.Status == OK {
		session.Active = false
		session.SharedKey = nil
		session.UserID = ""
		session.VerificationKey = nil
		session.PeerName = ""
	}
}

// Regular operation handler
func doOp(request *Request, response *Response) {
	response.Status = FAIL
	response.Uid = session.UserID

	if session.Active {
		switch request.Op {
		case NOOP:
			// NOTHING
		case CREATE:
			doCreate(request, response)
		case DELETE:
			doDelete(request, response)
		case READ:
			doReadVal(request, response)
		case WRITE:
			doWriteVal(request, response)
		case COPY:
			doCopy(request, response)
		case LOGOUT:
			doLogout(request, response)
		default:
			// struct already default initialized to FAIL status
		}
	} else {
		// Only login is allowed when no session is active
		if request.Op == LOGIN {
			// Regular login is not supported, only secure authentication
			// Keep response.Status as FAIL
		}
	}
}

// Input: key k, value v, metaval m. Returns a response.
// Sets the value and metaval for key k in the
// key-value store to value v and metavalue m.
func doCreate(request *Request, response *Response) {
	if _, ok := kvstore[request.Key]; !ok {
		kvstore[request.Key] = request.Val
		response.Status = OK
	}
}

// Input: key k. Returns a response. Deletes key from
// key-value store. If key does not exist then take no
// action.
func doDelete(request *Request, response *Response) {
	if _, ok := kvstore[request.Key]; ok {
		delete(kvstore, request.Key)
		response.Status = OK
	}
}

// Input: key k. Returns a response with the value
// associated with key. If key does not exist
// then status is FAIL.
func doReadVal(request *Request, response *Response) {
	if v, ok := kvstore[request.Key]; ok {
		response.Val = v
		response.Status = OK
	}
}

// Input: key k and value v. Returns a response.
// Change value in the key-value store associated
// with key k to value v. If key does not exist
// then status is FAIL.
func doWriteVal(request *Request, response *Response) {
	if _, ok := kvstore[request.Key]; ok {
		kvstore[request.Key] = request.Val
		response.Status = OK
	}
}

// Copy function - copies the value from src_key to dst_key
// Both keys must exist for the operation to succeed
func doCopy(request *Request, response *Response) {
	// First check if source key exists
	if srcVal, srcOk := kvstore[request.Src_key]; srcOk {
		// Then check if destination key exists
		if _, dstOk := kvstore[request.Dst_key]; dstOk {
			// Copy the value
			kvstore[request.Dst_key] = srcVal
			response.Status = OK
		}
	}
}

// Process authentication-based login request
func processAuthLogin(authRequest *AuthRequest, clientName string, response *Response, authResponse *AuthResponse) {
	response.Status = FAIL
	
	if session.Active {
		// Someone is already logged in
		return
	}
	
	// 1. Decrypt shared key
	sharedKey, err := crypto_utils.DecryptPK(authRequest.SharedKeyEncrypted, privateKey)
	if err != nil {
		fmt.Println("Failed to decrypt shared key:", err)
		return
	}
	
	// 2. Decrypt client message
	decryptedBytes, err := crypto_utils.DecryptSK(authRequest.MessageEncrypted, sharedKey)
	if err != nil {
		fmt.Println("Failed to decrypt client message:", err)
		return
	}
	
	// 3. Parse client auth message
	var clientAuthMessage AuthMessage
	if err := json.Unmarshal(decryptedBytes, &clientAuthMessage); err != nil {
		fmt.Println("Failed to unmarshal client auth message:", err)
		return
	}
	
	// 4. Verify client auth message
	valid, err, clientVerificationKey := auth_utils.VerifyAuthMessage(clientAuthMessage, clientName, "")
	
	if err != nil {
		fmt.Println("Error verifying client message:", err)
		return
	}
	
	if !valid {
		fmt.Println("Client verification failed")
		return
	}
	
	// 5. Create server's auth message
	opString := string(rune(LOGIN))
	serverAuthMessage := auth_utils.CreateAuthMessage(
		name,
		clientAuthMessage.Uid,
		opString,
		crypto_utils.PublicKeyToBytes(publicKey),
		privateKey,
	)
	
	// 6. Marshal and encrypt server auth message
	serverAuthMessageBytes, err := json.Marshal(serverAuthMessage)
	if err != nil {
		fmt.Println("Failed to marshal server auth message:", err)
		return
	}
	
	// 7. Create auth response
	*authResponse = AuthResponse{
		MessageEncrypted: crypto_utils.EncryptSK(serverAuthMessageBytes, sharedKey),
	}
	
	// 8. Update session state
	session.Active = true
	session.SharedKey = sharedKey
	session.UserID = clientAuthMessage.Uid
	session.VerificationKey = clientVerificationKey
	session.PeerName = clientName
	
	// 9. Update binding table
	BindingTable[session.UserID] = BindingTableData{
		ClientVerificationKey: clientVerificationKey,
		RecentLoginTime:       crypto_utils.ReadClock(),
	}
	
	// 10. Update response status
	response.Status = OK
	response.Uid = session.UserID
}

// When the session is active allow logout
func doLogout(request *Request, response *Response) {
	if session.Active {
		response.Status = OK
		response.Uid = session.UserID
		
		// Clear client key from binding table
		if data, exists := BindingTable[session.UserID]; exists {
			data.ClientVerificationKey = nil
			BindingTable[session.UserID] = data
		}
	}
}