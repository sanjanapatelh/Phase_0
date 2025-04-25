package types

type Code int

const (
	OK Code = iota
	FAIL
)

type Response struct {
	Status    Code        `json:"status"`
	Val       interface{} `json:"val"`
	Uid       string      `json:"uid"`
	Writers   []string    `json:"writers,omitempty"`
	Readers   []string    `json:"readers,omitempty"`
	Copytos   []string    `json:"copytos,omitempty"`
	Copyfroms []string    `json:"copyfroms,omitempty"`
	Indirects []string    `json:"indirects,omitempty"`
	R_k       []string    `json:"r(k),omitempty"`
	W_k       []string    `json:"w(k),omitempty"`
	C_Src_k   []string    `json:"c_src(k),omitempty"`
	C_Dst_k   []string    `json:"c_dst(k),omitempty"`
}
