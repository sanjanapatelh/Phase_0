package server

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"crypto_utils"
	. "types"
)

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey

var name string
var kvstore map[string]interface{}
var Requests chan NetworkData
var Responses chan NetworkData

var (
	AuthRequests  = make(chan AuthNetworkData, 10)
	AuthResponses = make(chan AuthNetworkData, 10)
)

//code changes begin

var current_user string
var session_active bool
var BindingTable map[string]BindingTableData

// code changes End

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

	go receiveThenSend()
	go ReceivedThenSendAuth()
}

func receiveThenSend() {
	defer close(Responses)

	for request := range Requests {
		Responses <- process(request)
	}
}

// ReceivedThenSendAuth handles auth channel communication
func ReceivedThenSendAuth() {
	defer close(AuthResponses)

	for authRequest := range AuthRequests {
		AuthResponses <- doLogin(authRequest)
	}
}

// Input: a byte array representing a request from a client.
// Deserializes the byte array into a request and performs
// the corresponding operation. Returns the serialized
// response. This method is invoked by the network.
func process(requestData NetworkData) NetworkData {

	var request Request
	json.Unmarshal(requestData.Payload, &request)
	var response Response
	doOp(&request, &response)
	responseBytes, _ := json.Marshal(response)
	return NetworkData{Payload: responseBytes, Name: name}
}

// Input: request from a client. Returns a response.
// Parses request and handles a switch statement to
// return the corresponding response to the request's
// operation.
func doOp(request *Request, response *Response) {

	response.Status = FAIL
	response.Uid = current_user

	if session_active {

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
			// struct already default initialized to
			// FAIL status
		}
	}

}

/** begin operation methods **/
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

// Code changes begin

// Copy function
func doCopy(request *Request, response *Response) {
	// Check for src_key abd dst_key being empty
	// Assign the value of requested src_key value to det_key
	if _, ok := kvstore[request.Src_key]; ok {
		if _, ok := kvstore[request.Dst_key]; ok {
			kvstore[request.Dst_key] = kvstore[request.Src_key]
			response.Status = OK
		}

	}
}

// Login
// Create session for the user and doesnot allow any other user to login.
func doLogin(authData AuthNetworkData) AuthNetworkData {
	messageFromClient := authData.Payload
	
	// Check if there's already an active session
	if session_active {
		fmt.Println("Error: Session already active for user:", current_user)
		return AuthNetworkData{
			Name:    name,
			Payload: nil,
		}
	}
	
	if messageFromClient == nil {
		fmt.Println("Message is empty")
		return AuthNetworkData{
			Name:    name,
			Payload: nil,
		}
	}

	// Parse client message
	messageClientToServer := MessageClientToServer{}
	if err := json.Unmarshal(messageFromClient, &messageClientToServer); err != nil {
		fmt.Println("Error: Failed to unmarshal client message:", err)
		return AuthNetworkData{
			Name:    name,
			Payload: nil,
		}
	}

	// Decrypt shared key
	sharedKeyEncrypted := messageClientToServer.SharedKeyEncrypted
	if sharedKeyEncrypted == nil || len(sharedKeyEncrypted) == 0 {
		fmt.Println("Error: Shared key is empty")
		return AuthNetworkData{
			Name:    name,
			Payload: nil,
		}
	}

	sharedKey, err := crypto_utils.DecryptPK(sharedKeyEncrypted, privateKey)
	if err != nil {
		fmt.Println("Error: Failed to decrypt shared key:", err)
		return AuthNetworkData{
			Name:    name,
			Payload: nil,
		}
	}

	// Decrypt message contents using shared key
	encryptedContentsBytes := messageClientToServer.MessageEncrypted
	decryptedMessageBytes, err := crypto_utils.DecryptSK(encryptedContentsBytes, sharedKey)
	if err != nil {
		fmt.Println("Error: Failed to decrypt message contents:", err)
		return AuthNetworkData{
			Name:    name,
			Payload: nil,
		}
	}

	clientToServerMessageContents := ClientToServerEncryptedContents{}
	if err := json.Unmarshal(decryptedMessageBytes, &clientToServerMessageContents); err != nil {
		fmt.Println("Error: Failed to unmarshal decrypted contents:", err)
		return AuthNetworkData{
			Name:    name,
			Payload: nil,
		}
	}

	// Build signing message for verification
	signingMessage := []byte(clientToServerMessageContents.Name + clientToServerMessageContents.Uid + clientToServerMessageContents.Op)
	signingMessage = append(signingMessage, clientToServerMessageContents.TimeOfDay...)
	signingMessage = append(signingMessage, clientToServerMessageContents.ClientVerificationKey...)

	// Parse client verification key
	clientVerificationKey, err := crypto_utils.BytesToPublicKey(clientToServerMessageContents.ClientVerificationKey)
	if err != nil {
		fmt.Println("Error: Failed to parse client verification key:", err)
		return AuthNetworkData{
			Name:    name,
			Payload: nil,
		}
	}

	currentTime := crypto_utils.ReadClock()
	clientTime := crypto_utils.BytesToTod(clientToServerMessageContents.TimeOfDay)

	// Check signature validity
	validSignature := crypto_utils.Verify(
		clientToServerMessageContents.Signature, 
		crypto_utils.Hash(signingMessage), 
		clientVerificationKey)
	
	// Check name matching and time validity
	validName := strings.EqualFold(messageClientToServer.Name, clientToServerMessageContents.Name)
	validTime := clientTime.Before(currentTime) && currentTime.Sub(clientTime) <= 5*time.Minute

	if !validSignature || !validName || !validTime {
		fmt.Println("Error: Client verification failed")
		return AuthNetworkData{
			Name:    name,
			Payload: nil,
		}
	}

	// Get user ID from the request
	uid := clientToServerMessageContents.Uid

	// Create server's response
	timeOfDay := crypto_utils.TodToBytes(currentTime)
	
	opString := "LOGIN"
	
	serverSigningMessage := []byte(name + uid + opString)
	serverSigningMessage = append(serverSigningMessage, timeOfDay...)
	serverVerificationKeyBytes := crypto_utils.PublicKeyToBytes(publicKey)
	serverSigningMessage = append(serverSigningMessage, serverVerificationKeyBytes...)
	
	// Sign server message with proper hashing
	serverSignature := crypto_utils.Sign(serverSigningMessage, privateKey)

	// Create encrypted contents of the message
	serverMessageContents := ServerToClientEncryptedContents{
		Name:                  name,
		Uid:                   uid,
		Op:                    opString,
		ServerVerificationKey: serverVerificationKeyBytes,
		TimeOfDay:             timeOfDay,
		Signature:             serverSignature,
	}

	serverMessage, err := json.Marshal(serverMessageContents)
	if err != nil {
		fmt.Println("Error: Failed to marshal server contents:", err)
		return AuthNetworkData{
			Name:    name,
			Payload: nil,
		}
	}

	// Create server's message to client
	messageToClientBytes, _ := json.Marshal(MessageServerToClient{
		Name:             name,
		MessageEncrypted: crypto_utils.EncryptSK(serverMessage, sharedKey),
	})

	// Save the session info to binding table
	BindingTable[uid] = BindingTableData{
		ClientVerificationKey: clientVerificationKey,
		RecentLoginTime:       currentTime,
		IsActive:              true,
	}
	
	// Set active session
	session_active = true
	current_user = uid
	
	fmt.Println("Authentication successful for user:", uid)
	
	return AuthNetworkData{
		Name:    name,
		Payload: messageToClientBytes,
	}
}

// IsAuthenticated checks if a user is authenticated
func IsAuthenticated(uid string) bool {
	session, exists := BindingTable[uid]
	return exists && session.IsActive
}

// GetSessionKey retrieves the session key for an authenticated user
// func GetSessionKey(uid string) []byte {
// 	if session, exists := BindingTable[uid]; exists && session.IsActive {
// 		return session.SessionKey
// 	}
// 	return nil
// }

// InvalidateSession removes a user's session
// func InvalidateSession(uid string) {
// 	delete(BindingTableData, uid)
// }

// When the session is active all the session to logout
func doLogout(request *Request, response *Response) {
	if session_active {
		session_active = false
		response.Status = OK
		response.Uid = current_user
		current_user = ""

		// delete  data from binding table
		if data, exists := BindingTable[request.Uid]; exists {
			data.ClientVerificationKey = nil // Remove verification key
			BindingTable[request.Uid] = data         // Update the entry
		}
		//

	}
}
