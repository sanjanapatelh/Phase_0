package client

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"server"
	"strings"

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

	// encrypt shared key using server's public key
	sharedKey := crypto_utils.NewSessionKey()
	sharedKeyEncrypted := crypto_utils.EncryptPK(sharedKey, serverPublicKey)

	// mint client's signature
	timeOfDay := crypto_utils.TodToBytes(crypto_utils.ReadClock())
	signingMessage := []byte(name + request.Uid + string(rune(request.Op)))
	signingMessage = append(signingMessage, timeOfDay...)
	clientSigningKey := crypto_utils.NewPrivateKey()
	signingMessage = append(signingMessage, crypto_utils.PublicKeyToBytes(&clientSigningKey.PublicKey)...)
	clientSignature := crypto_utils.Sign(signingMessage, clientSigningKey)

	// create encrypted contents of the message
	encryptedContentsBytes, _ := json.Marshal(server.ClientToServerEncryptedContents{Name: name, Uid: request.Uid, Op: string(rune(request.Op)), ClientVerificationKey: crypto_utils.PublicKeyToBytes(&clientSigningKey.PublicKey), TimeOfDay: timeOfDay, Signature: clientSignature})

	// add client's mesage to server as part of the request
		messageToServerBytes, _ := json.Marshal(server.MessageClientToServer{Name: name, SharedKeyEncrypted: sharedKeyEncrypted, MessageEncrypted: crypto_utils.EncryptSK(encryptedContentsBytes, sharedKey)})
	request.Message = append(request.Message, messageToServerBytes...)

	doOp(request, response)

	messageFromServer := response.Message

	if messageFromServer == nil {
		fmt.Println("Message is empty")
		return
	}

	MessageServerToClient := server.MessageServerToClient{}
	json.Unmarshal(messageFromServer, &MessageServerToClient)

	encryptedContentsBytesServer := MessageServerToClient.MessageEncrypted
	decryptedMessageBytesServer, _ := crypto_utils.DecryptSK(encryptedContentsBytesServer, sharedKey)
	serverToClientMessageContents := server.ServerToClientEncryptedContents{}
	json.Unmarshal(decryptedMessageBytesServer, &serverToClientMessageContents)

	serverSignature := serverToClientMessageContents.Signature
	serverSigningMessage := []byte(serverToClientMessageContents.Name + serverToClientMessageContents.Uid + serverToClientMessageContents.Op)
	serverSigningMessage = append(serverSigningMessage, serverToClientMessageContents.TimeOfDay...)
	serverSigningMessage = append(serverSigningMessage, serverToClientMessageContents.ServerVerificationKey...)
	serverVerificationKey, _ := crypto_utils.BytesToPublicKey(serverToClientMessageContents.ServerVerificationKey)

	fmt.Println(serverToClientMessageContents.Name, MessageServerToClient.Name , "verify servers dignature")

	if crypto_utils.Verify(serverSignature, crypto_utils.Hash(serverSigningMessage), serverVerificationKey) && 
	   strings.EqualFold(serverToClientMessageContents.Name, MessageServerToClient.Name) && 
	   crypto_utils.BytesToTod(serverToClientMessageContents.TimeOfDay).Before(crypto_utils.ReadClock()) {
		fmt.Println("Login succeeded party by Sanjana!!!!")
	}
}

func doOp(request *Request, response *Response) {
	requestBytes, _ := json.Marshal(request)
	json.Unmarshal(sendAndReceive(NetworkData{Payload: requestBytes, Name: name}).Payload, &response)
}

func sendAndReceive(toSend NetworkData) NetworkData {
	Requests <- toSend
	return <-Responses
}
