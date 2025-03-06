package network

import (
	"client"
	"fmt"
	"server"
	. "types"
)

// Message counter
var messageCount = 0

// Stored first message for replay
var firstMessage NetworkData

// Initialize network
func init() {
	fmt.Println("Network initialized - Will replay first message on third request")
	client.ObtainServerPublicKey()
	// Start network relays
	go clientToServer()
	go serverToClient()
}

// Relay messages from client to server
func clientToServer() {
	for {
		request := <-client.Requests
		messageCount++
		
		fmt.Printf("\nHandling message #%d...\n", messageCount)
		
		// Store first message for later replay
		if messageCount == 1 {
			firstMessage = request
			fmt.Println("Stored first message for later replay")
		}
		
		// On the third message, replay the first message instead
		if messageCount == 3 {
			fmt.Println("\n***** ATTACK: Replaying first message instead of sending third message *****")
			server.Requests <- firstMessage
		} else {
			// Normal relay for all other messages
			server.Requests <- request
		}
	}
}

// Relay messages from server to client
func serverToClient() {
	for {
		response := <-server.Responses
		
		// When receiving response to the third message (which is our attack)
		if messageCount == 3 {
			// Try to determine if attack was detected or not
			if len(response.Payload) > 0 && response.Payload[0] == '{' {
				// Looks like a JSON response, check for patterns
				respStr := string(response.Payload)
				if contains(respStr, "FAIL") {
					fmt.Println("\n✓ SECURITY SUCCESS: System rejected the replayed message!")
				} else if contains(respStr, "OK") {
					fmt.Println("\n✗ SECURITY ISSUE: System accepted the replayed message!")
				}
			}
		}
		
		// Forward response to client
		client.Responses <- response
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[0:len(substr)] == substr
}