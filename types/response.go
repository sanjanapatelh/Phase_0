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
	Writers   []string `json:"writers"`
    Readers   []string `json:"readers"`
    Copytos   []string `json:"copytos"`
    Copyfroms []string `json:"copyfroms"`
    Indirects []string `json:"indirects"`
    Rk        []string `json:"r(k)"`
    Wk        []string `json:"w(k)"`
    CSrck     []string `json:"c_src(k)"`
    CDstk     []string `json:"c_dst(k)"`
}
