package client

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"os"

	"github.com/google/uuid"

	"crypto_utils"
	. "types"
)

var name string
var Requests chan NetworkData
var Responses chan NetworkData

var serverPublicKey *rsa.PublicKey

func init() {
	name = uuid.NewString()
	Requests = make(chan NetworkData)
	Responses = make(chan NetworkData)
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
		case CREATE, DELETE, READ, WRITE, COPY, LOGOUT:
			doOp(request, response)
		case LOGIN:
			doLogin(request, response)
		default:
			// struct already default initialized to
			// FAIL status
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

func doLogin(request *Request, response *Response){

	// 1. Generate and encrypt shared key using server's public key
	sharedKey := crypto_utils.NewSessionKey()
	if sharedKey == nil {
		fmt.Println("Failed to generate session key")
		return
	}
	sharedKeyEncrypted := crypto_utils.EncryptPK(sharedKey, serverPublicKey)

	// 2. Prepare client's signature with proper data
	currentTOD := crypto_utils.ReadClock()
	timeOfDay := crypto_utils.TodToBytes(currentTOD)

	// Generate a new signing key for this session
	clientSigningKey := crypto_utils.NewPrivateKey()
	clientVerificationKey := crypto_utils.PublicKeyToBytes(&clientSigningKey.PublicKey)

	// Build the signing message with all components
	signingMessage := []byte(name + request.Uid + string(rune(request.Op)))
	signingMessage = append(signingMessage, timeOfDay...)
	signingMessage = append(signingMessage, clientVerificationKey...)

	clientSignature := crypto_utils.Sign(signingMessage, clientSigningKey)

	// 3. Create encrypted contents with proper error handling
	encryptedContents := ClientToServerEncryptedContents{
		Name:                 name,
		Uid:                  request.Uid,
		Op:                   string(rune(request.Op)),
		ClientVerificationKey: clientVerificationKey,
		TimeOfDay:            timeOfDay,
		Signature:            clientSignature,
	}

	encryptedContentsBytes, err := json.Marshal(encryptedContents)
	if err != nil {
		fmt.Println("Failed to marshal encrypted contents:", err)
		return
	}

	// 4. Create the message to server - assign rather than append
	messageToServer := MessageClientToServer{
		Name:               name,
		SharedKeyEncrypted: sharedKeyEncrypted,
		MessageEncrypted:   crypto_utils.EncryptSK(encryptedContentsBytes, sharedKey),
	}

	messageToServerBytes, err := json.Marshal(messageToServer)
	if err != nil {
		fmt.Println("Failed to marshal message to server:", err)
		return
	}

	request.Message = messageToServerBytes

	doOp(request, response)

	if response.Status != OK {
		fmt.Printf("Server returned error status: %v\n", response.Status)
		return
	}

	messageFromServer := response.Message

	if messageFromServer == nil {
		fmt.Println("Message is empty")
		return
	}

	serverMessage := MessageServerToClient{}
	if err := json.Unmarshal(messageFromServer, &serverMessage); err != nil {
		fmt.Println("Failed to unmarshal server message:", err)
		return
	}

	encryptedContentsBytesServer := serverMessage.MessageEncrypted
	decryptedMessageBytes, err := crypto_utils.DecryptSK(encryptedContentsBytesServer, sharedKey)
	if err != nil {
		fmt.Println("Failed to decrypt server message:", err)
		return
	}
	serverContents := ServerToClientEncryptedContents{}
	if err := json.Unmarshal(decryptedMessageBytes, &serverContents); err != nil {
		fmt.Println("Failed to unmarshal server contents:", err)
		return
	}

	// 9. Verify server's identity and signature
	serverVerificationKey, err := crypto_utils.BytesToPublicKey(serverContents.ServerVerificationKey)
	if err != nil {
		fmt.Println("Failed to parse server verification key:", err)
		return
	}
	
	// Build server signing message for verification
	serverSigningMessage := []byte(serverContents.Name + serverContents.Uid + serverContents.Op)
	serverSigningMessage = append(serverSigningMessage, serverContents.TimeOfDay...)
	serverSigningMessage = append(serverSigningMessage, serverContents.ServerVerificationKey...)

	// Check server's time of day
	serverTOD := crypto_utils.BytesToTod(serverContents.TimeOfDay)
	if !serverTOD.Before(crypto_utils.ReadClock().Add(5 * time.Minute)) {
		fmt.Println("Server time of day is too far in the future")
		return
	}
	
	if crypto_utils.ReadClock().Sub(serverTOD) > 5*time.Minute {
		fmt.Println("Server time of day is too old")
		return
	}
	
	// Verify all security components
	validSignature := crypto_utils.Verify(
		serverContents.Signature, 
		crypto_utils.Hash(serverSigningMessage), 
		serverVerificationKey,
	)
	
	namesMatch := strings.EqualFold(serverContents.Name, serverMessage.Name)
	uidMatch := serverContents.Uid == request.Uid
	
	// 10. Process verification results
	if !validSignature {
		fmt.Println("Server signature verification failed")
		return
	}
	
	if !namesMatch {
		fmt.Printf("Server name mismatch: expected %s, got %s\n", 
			serverMessage.Name, serverContents.Name)
		return
	}
	
	if !uidMatch {
		fmt.Printf("User ID mismatch: expected %s, got %s\n", 
			request.Uid, serverContents.Uid)
		return
	}
	
	fmt.Println("Login succeeded! All verifications passed.")
	response.Message = nil
}

func doOp(request *Request, response *Response) {
	requestBytes, _ := json.Marshal(request)
	json.Unmarshal(sendAndReceive(NetworkData{Payload: requestBytes, Name: name}).Payload, &response)
}

func sendAndReceive(toSend NetworkData) NetworkData {
	Requests <- toSend
	return <-Responses
}
