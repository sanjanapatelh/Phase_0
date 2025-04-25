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
	Writers   []string    `json:"writers"`
	Readers   []string    `json:"readers"`
	Copytos   []string    `json:"copytos"`
	Copyfroms []string    `json:"copyfroms"`
	Indirects []string    `json:"indirects"`
	R_k       []string    `json:"r(k)"`
	W_k       []string    `json:"w(k)"`
	C_Src_k   []string    `json:"c_src(k)"`
	C_Dst_k   []string    `json:"c_dst(k)"`
}
