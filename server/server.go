package server

import (
	"crypto/rsa"
	"encoding/json"
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

	session = auth_utils.InitSessionData(name, privateKey)

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
		var secureMessage SecureMessage
		if err := json.Unmarshal(requestData.Payload, &secureMessage); err == nil {
			// This is a secure request during an active session
			processSecureRequest(&secureMessage, &responseBytes)
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
func processSecureRequest(secureMessage *SecureMessage, responseBytes *[]byte) {
	// Default failure response
	response := Response{Status: FAIL, Uid: session.UserID}
	secureResponseMessage, err := auth_utils.EncryptResponse(&response, session)
	if err != nil {
		secureResponseBytes, _ := json.Marshal(secureResponseMessage)
		*responseBytes = secureResponseBytes
		return
	}
	
	// 1. Decrypt and verify the secure request
	request, valid, err := auth_utils.DecryptRequest(secureMessage, session)
	if err != nil || !valid {
		secureResponseBytes, _ := json.Marshal(secureResponseMessage)
		*responseBytes = secureResponseBytes
		return
	}
	
	// 2. Process the regular operation
	doOp(request, &response)
	
	// 3. Encrypt the response
	secureResponseMessage, err = auth_utils.EncryptResponse(&response, session)
	if err != nil {
		secureResponseBytes, _ := json.Marshal(secureResponseMessage)
		*responseBytes = secureResponseBytes
		return
	}
	
	// 4. Marshal the secure response
	secureResponseBytes, _ := json.Marshal(secureResponseMessage)
	*responseBytes = secureResponseBytes
	
	// 5. Special handling for logout
	if request.Op == LOGOUT && response.Status == OK {
		session.Active = false
		session.SharedKey = nil
		session.UserID = ""
		session.VerificationKey = nil
		// Clear nonce map on logout
		if session.SeenNonces != nil {
			session.SeenNonces = make(map[string]bool)
		}
	}
}

// Process authentication-based login request
func processAuthLogin(authRequest *AuthRequest, clientName string, response *Response, authResponse *AuthResponse) {
	response.Status = FAIL
	
	if session.Active {
		response.Status = FAIL
		return
	}
	
	// 1. Decrypt shared key
	sharedKey, err := crypto_utils.DecryptPK(authRequest.SharedKeyEncrypted, privateKey)
	if err != nil {
		response.Status = FAIL
		return
	}
	
	// 2. Verify and decrypt client message
	// First, we need to parse the client verification key
	// Since we don't have it yet, we'll need to do this in two phases
	
	// a) First, decrypt the client's message
	decryptedBytes, err := crypto_utils.DecryptSK(authRequest.MessageEncrypted, sharedKey)
	if err != nil {
		response.Status = FAIL
		return
	}
	
	// b) Parse the encrypted content to get the client verification key
	var encryptedContent AuthEncryptedContent
	if err := json.Unmarshal(decryptedBytes, &encryptedContent); err != nil {
		response.Status = FAIL
		return
	}
	
	// c) Parse the inner message to get the client verification key
	var innerClientMessage InnerAuthMessage
	if err := json.Unmarshal(encryptedContent.InnerMessage, &innerClientMessage); err != nil {
		response.Status = FAIL
		return
	}
	
	// d) Parse the client verification key
	clientVerificationKey, err := crypto_utils.BytesToPublicKey(innerClientMessage.VerificationKey)
	if err != nil {
		response.Status = FAIL
		return
	}
	
	// e) Now verify the signature
	validSignature := crypto_utils.Verify(
		encryptedContent.Signature,
		crypto_utils.Hash(encryptedContent.InnerMessage),
		clientVerificationKey,
	)
	
	if !validSignature {
		response.Status = FAIL
		return
	}
	
	// f) Verify time of day (freshness)
	messageTOD := crypto_utils.BytesToTod(innerClientMessage.TimeOfDay)
	currentTOD := crypto_utils.ReadClock()

	bindingData, exists := BindingTable[innerClientMessage.Uid]
	if exists {
		recentLoginTime := bindingData.RecentLoginTime
		
		// Message time should be after login time and before current time
		if !(recentLoginTime.Before(messageTOD) && messageTOD.Before(currentTOD)) {
			response.Status = FAIL
			return
		}
	}

	// For new users (first login), we only check that the message time is before current time
	if !exists && !messageTOD.Before(currentTOD) {
		response.Status = FAIL
		return
	}
	
	// g) Check if nonce has been seen before
	if !auth_utils.CheckAndRecordAuthNonce(innerClientMessage.Nonce) {
		response.Status = FAIL
		return
	}
	
	// h) Verify the client's name matches
	if innerClientMessage.Name != clientName {
		response.Status = FAIL
		return
	}
	
	// 3. Create server's auth message
	serverAuthContentBytes, err := auth_utils.CreateAuthMessage(
		name,
		innerClientMessage.Uid,
		string(rune(LOGIN)),
		crypto_utils.PublicKeyToBytes(publicKey),
		privateKey,
	)
	
	if err != nil {
		response.Status = FAIL
		return
	}
	
	// 4. Encrypt the server's auth content with shared key
	encryptedServerAuthBytes := auth_utils.EncryptAuthMessage(serverAuthContentBytes, sharedKey)
	
	// 5. Create auth response
	*authResponse = AuthResponse{
		MessageEncrypted: encryptedServerAuthBytes,
	}
	
	// 6. Update session state
	session.Active = true
	session.SharedKey = sharedKey
	session.UserID = innerClientMessage.Uid
	session.VerificationKey = clientVerificationKey
	
	// 7. Update binding table
	BindingTable[session.UserID] = BindingTableData{
		ClientVerificationKey: clientVerificationKey,
		RecentLoginTime:       crypto_utils.ReadClock(),
	}
	
	// 8. Update response status
	response.Status = OK
	response.Uid = session.UserID
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