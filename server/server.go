package server

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"strings"

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

//code changes begin

var current_user string
var session_active bool

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
	Requests = make(chan NetworkData)
	Responses = make(chan NetworkData)

	go receiveThenSend()
}

func receiveThenSend() {
	defer close(Responses)

	for request := range Requests {
		Responses <- process(request)
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
		case LOGIN:
			doLogin(request, response)
		case LOGOUT:
			doLogout(request, response)

		default:
			// struct already default initialized to
			// FAIL status
		}

	} else {
		if request.Op == 6 {
			doLogin(request, response)
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
func doLogin(request *Request, response *Response) {

	if !session_active {
		messageFromClient := request.Message
		if messageFromClient == nil {
			fmt.Println("Message is empty")
			return
		}
		messageClientToServer := MessageClientToServer{}
		json.Unmarshal(messageFromClient, &messageClientToServer)

		// decrypt shared key
		sharedKeyEncrypted := messageClientToServer.SharedKeyEncrypted
		sharedKey, _ := crypto_utils.DecryptPK(sharedKeyEncrypted, privateKey)

		// decrypt message contents using shared key
		encryptedContentsBytes := messageClientToServer.MessageEncrypted
		decryptedMessageBytes, _ := crypto_utils.DecryptSK(encryptedContentsBytes, sharedKey)
		clientToServerMessageContents := ClientToServerEncryptedContents{}
		json.Unmarshal(decryptedMessageBytes, &clientToServerMessageContents)

		clientSignature := clientToServerMessageContents.Signature
		signingMessage := []byte(clientToServerMessageContents.Name + clientToServerMessageContents.Uid + clientToServerMessageContents.Op)
		signingMessage = append(signingMessage, clientToServerMessageContents.TimeOfDay...)
		clientVerificationKey, _ := crypto_utils.BytesToPublicKey(clientToServerMessageContents.ClientVerificationKey)

		// verify client's signature, name and tod
		if !crypto_utils.Verify(clientSignature, crypto_utils.Hash(signingMessage), clientVerificationKey) || !strings.EqualFold(messageClientToServer.Name, clientToServerMessageContents.Name) || !crypto_utils.BytesToTod(clientToServerMessageContents.TimeOfDay).Before(crypto_utils.ReadClock()) {
			return
		}

		session_active = true
		current_user = request.Uid
		response.Status = OK
		response.Uid = request.Uid
	}
}

// When the session is active all the session to logout
func doLogout(request *Request, response *Response) {
	if session_active {
		session_active = false
		response.Status = OK
		response.Uid = current_user
		current_user = ""
	}
}

// PrintPrettyJSON prints the input data in a pretty JSON format. Can be removed after testing.
func PrintPrettyJSON(input interface{}) {
	jsonData, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling JSON:", err)
		return
	}
	fmt.Print(string(jsonData), " ")
}

// MserverStructure holds the components for secure communication
type MessageClientToServer struct {
	Name               string `json:"name"`
	SharedKeyEncrypted []byte `json:"shared_key_encrypted"`
	MessageEncrypted   []byte `json:"message_encrypted"`
}

type ClientToServerEncryptedContents struct {
	Name                  string `json:"name"`
	Uid                   string `json:"uid"`
	Op                    string `json:"op"`
	ClientVerificationKey []byte `json:"client_public_key"`
	TimeOfDay             []byte `json:"time_of_day"`
	Signature             []byte `json:"signature"`
}
