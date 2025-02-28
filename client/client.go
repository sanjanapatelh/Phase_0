package client

import (
	"crypto/rsa"
	"encoding/json"

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
	case LOGOUT :
		return true
	default:
		return false
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
