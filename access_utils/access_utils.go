package access_utils

import (
	. "types"
)

func IsInReaderSet(key string, uid string, kvstore map[string]KeyValue) bool {
	// Get the key-value pair from the store
	keyValue, ok := kvstore[key]
	if !ok {
		// Key does not exist, return false
		return false
	}

	// Check if the user is in the readers set
	if _, ok := keyValue.Readers[uid]; ok {
		return true
	}

	// Check if the user is in any of the indirect sets
	for indirect := range keyValue.Indirects {
		if _, ok := kvstore[indirect]; ok {
			if IsInReaderSet(indirect, uid, kvstore) {
				return true
			}
		}
	}

	// User is not in the readers set or any indirect sets
	return false
}

func IsInWriterSet(key string, uid string, kvstore map[string]KeyValue) bool {
	// Get the key-value pair from the store
	keyValue, ok := kvstore[key]
	if !ok {
		// Key does not exist, return false
		return false
	}

	// Check if the user is in the writers set
	if _, ok := keyValue.Writers[uid]; ok {
		return true
	}

	// Check if the user is in any of the indirect sets
	for indirect := range keyValue.Indirects {
		if _, ok := kvstore[indirect]; ok {
			if IsInWriterSet(indirect, uid, kvstore) {
				return true
			}
		}
	}

	// User is not in the writers set or any indirect sets
	return false
}

func IsInCopyToSet(key string, uid string, kvstore map[string]KeyValue) bool {
	// Get the key-value pair from the store
	keyValue, ok := kvstore[key]
	if !ok {
		// Key does not exist, return false
		return false
	}

	// Check if the user is in the copyto set
	if _, ok := keyValue.Copytos[uid]; ok {
		return true
	}

	// Check if the user is in any of the indirect sets
	for indirect := range keyValue.Indirects {
		if _, ok := kvstore[indirect]; ok {
			if IsInCopyToSet(indirect, uid, kvstore) {
				return true
			}
		}
	}

	// User is not in the copyto set or any indirect sets
	return false
}

func IsInCopyFromSet(key string, uid string, kvstore map[string]KeyValue) bool {
	// Get the key-value pair from the store
	keyValue, ok := kvstore[key]
	if !ok {
		// Key does not exist, return false
		return false
	}

	// Check if the user is in the copyfrom set
	if _, ok := keyValue.Copyfroms[uid]; ok {
		return true
	}

	// Check if the user is in any of the indirect sets
	for indirect := range keyValue.Indirects {
		if _, ok := kvstore[indirect]; ok {
			if IsInCopyFromSet(indirect, uid, kvstore) {
				return true
			}
		}
	}

	// User is not in the copyfrom set or any indirect sets
	return false
}

// GetEffectiveReaderSet returns the effective set of readers for the given key.
// It is the union of the readers set and the readers sets of all the indirect sets.
func GetEffectiveReaderSet(key string, kvstore map[string]KeyValue) map[string]bool {
	result := make(map[string]bool)

	// If key exists, add its readers set to the result
	if v, ok := kvstore[key]; ok {
		for u := range v.Readers {
			result[u] = true
		}

		// Add the readers sets of all the indirect sets to the result
		for indirect := range v.Indirects {
			if _, ok := kvstore[indirect]; ok {
				for u := range GetEffectiveReaderSet(indirect, kvstore) {
					result[u] = true
				}
			}
		}
	}

	return result
}

// GetEffectiveWriterSet returns the effective set of writers for the given key.
// It is the union of the writers set and the writers sets of all the indirect sets.
func GetEffectiveWriterSet(key string, kvstore map[string]KeyValue) map[string]bool {
	// Initialize the result to an empty set
	result := make(map[string]bool)

	// If the key exists, add its writers set to the result
	if v, ok := kvstore[key]; ok {
		for u := range v.Writers {
			result[u] = true
		}

		// Add the writers sets of all the indirect sets to the result
		for indirect := range v.Indirects {
			if _, ok := kvstore[indirect]; ok {
				for u := range GetEffectiveWriterSet(indirect, kvstore) {
					result[u] = true
				}
			}
		}
	}

	// Return the complete set of effective writers
	return result
}

// GetEffectiveCopyFromSet returns the effective copy-from set for the given key.
// It's the union of the copyfrom set and the copyfrom sets of all the indirect sets.
func GetEffectiveCopyFromSet(key string, kvstore map[string]KeyValue) map[string]bool {
	result := make(map[string]bool)
	if v, ok := kvstore[key]; ok {
		// Add the copyfrom set of the key to the result
		for u := range v.Copyfroms {
			result[u] = true
		}
		// Add the copyfrom sets of all the indirect sets to the result
		for indirect := range v.Indirects {
			if _, ok := kvstore[indirect]; ok {
				for u := range GetEffectiveCopyFromSet(indirect, kvstore) {
					result[u] = true
				}
			}
		}
	}
	return result
}

// GetEffectiveCopyToSet returns the effective copy-to set for the given key.
// It's the union of the copyto set and the copyto sets of all the indirect sets.
func GetEffectiveCopyToSet(key string, kvstore map[string]KeyValue) map[string]bool {
	// Initialize the result to an empty set
	result := make(map[string]bool)

	// If the key exists, add its copyto set to the result
	if v, ok := kvstore[key]; ok {
		for u := range v.Copytos {
			result[u] = true
		}

		// Add the copyto sets of all the indirect sets to the result
		for indirect := range v.Indirects {
			if _, ok := kvstore[indirect]; ok {
				for u := range GetEffectiveCopyToSet(indirect, kvstore) {
					result[u] = true
				}
			}
		}
	}

	return result
}
