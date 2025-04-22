package types

type KeyValue struct {
    Val       interface{}
    Owner     string            // Principal who created the key
    Readers   map[string]bool   // Principals authorized to read
    Writers   map[string]bool   // Principals authorized to write
    Copyfroms map[string]bool   // Principals authorized to use as source in COPY
    Copytos   map[string]bool   // Principals authorized to use as destination in COPY
    Indirects map[string]bool   // Keys that augment access control sets
}