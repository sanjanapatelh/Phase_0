package types

type Code int

const (
	OK Code = iota
	FAIL
)

type Response struct {
	Status 	Code 		 `json:"status"`
	Val  	interface{}	 `json:"val"`
	Uid 	string 		 `json:"uid"`
	Message []byte `json:"message,omitempty"`
}
