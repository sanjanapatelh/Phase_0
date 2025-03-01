package types

type Operation int

const (
	NOOP Operation = iota
	CREATE
	DELETE
	READ
	WRITE
	COPY
	LOGIN
	LOGOUT
)

type Request struct {
	Key     string      `json:"key"`
	Val     interface{} `json:"val"`
	Op      Operation   `json:"op"`
	Src_key string      `json:"src_key"`
	Dst_key string      `json:"dst_key"`
	Uid     string      `json:"uid"`

	Message []byte `json:"message,omitempty"`
}
