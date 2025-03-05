package network

import (
	"client"
	"server"
)

func init() {
	client.ObtainServerPublicKey()

	go relay()

	// Start the authentication relay
	go authRelay()
}

func relay() {
	defer close(server.Requests)
	defer close(client.Responses)

	for request := range client.Requests {
		server.Requests <- request
		client.Responses <- (<- server.Responses)
	}
}

// Authentication data relay
func authRelay() {
	defer close(server.AuthRequests)
	defer close(client.AuthResponses)

	for authRequest := range client.AuthRequests {
		server.AuthRequests <- authRequest
		client.AuthResponses <- (<-server.AuthResponses)
	}
}