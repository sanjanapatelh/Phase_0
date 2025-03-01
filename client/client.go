package client

import (
	"crypto/rsa"
	"encoding/json"
	"server"

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
		case CREATE, DELETE, READ, WRITE, COPY, LOGIN, LOGOUT:
			doOp(request, response)
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

func doOp(request *Request, response *Response) {
	if request.Op == LOGIN {
		// encrypt shared key using server's public key
		sharedKey := crypto_utils.NewSessionKey()
		sharedKeyEncrypted := crypto_utils.EncryptPK(sharedKey, serverPublicKey)

		// mint client's signature
		signingMessage := []byte(name + request.Uid + string(rune(request.Op)))
		signingMessage = append(signingMessage, crypto_utils.TodToBytes(crypto_utils.ReadClock())...)
		signingKey := crypto_utils.NewPrivateKey()
		clientSignature := crypto_utils.Sign(crypto_utils.Hash(signingMessage), signingKey)

		// create encrypted contents of the message
		encryptedContentsBytes, _ := json.Marshal(server.ClientToServerEncryptedContents{Name: name, Uid: request.Uid, Op: string(rune(request.Op)), ClientPublicKey: crypto_utils.PublicKeyToBytes(&signingKey.PublicKey), TimeOfDay: crypto_utils.TodToBytes(crypto_utils.ReadClock()), Signature: clientSignature})

		// add client's mesage to server as part of the request
		messageToServerBytes, _ := json.Marshal(server.MessageClientToServer{Name: name, SharedKeyEncrypted: sharedKeyEncrypted, MessageEncrypted: crypto_utils.EncryptSK(encryptedContentsBytes, sharedKey)})
		request.Message = append(request.Message, messageToServerBytes...)
	}
	requestBytes, _ := json.Marshal(request)
	json.Unmarshal(sendAndReceive(NetworkData{Payload: requestBytes, Name: name}).Payload, &response)
}

func sendAndReceive(toSend NetworkData) NetworkData {
	Requests <- toSend
	return <-Responses
}
