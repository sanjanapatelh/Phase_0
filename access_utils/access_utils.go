package access_utils

import (
	"encoding/json"
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

func isInCopyToSet(key string, uid string, kvstore map[string]KeyValue) bool {
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
			if isInCopyToSet(indirect, uid, kvstore) {
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

// SaveAccessControlSets saves the access control sets to the underlying storage.
func SaveAccessControlSets(kvstore map[string]KeyValue) error {
	// Iterate over the key-value pairs in the store
	for key, keyValue := range kvstore {
		// Save the readers set
		if err := SaveSet(key, keyValue.Readers, "readers"); err != nil {
			return err
		}

		// Save the writers set
		if err := SaveSet(key, keyValue.Writers, "writers"); err != nil {
			return err
		}

		// Save the copyto set
		if err := SaveSet(key, keyValue.Copytos, "copyto"); err != nil {
			return err
		}

		// Save the copyfrom set
		if err := SaveSet(key, keyValue.Copyfroms, "copyfrom"); err != nil {
			return err
		}

		// Save the indirect sets
		if err := SaveIndirectSets(key, keyValue.Indirects); err != nil {
			return err
		}
	}

	return nil
}

// saveSet saves a single access control set to the underlying storage.
func SaveSet(key string, set map[string]bool, setName string) error {
	// Convert the set to a JSON-encoded string
	setJSON, err := json.Marshal(set)
	if err != nil {
		return err
	}

	// Save the set to the underlying storage
	// Replace this with your actual storage mechanism
	// For now, just print the set to the console
	println("Saving set:", setName, "for key:", key)
	println(string(setJSON))

	return nil
}

// saveIndirectSets saves the indirect sets to the underlying storage.
func SaveIndirectSets(key string, indirects map[string]bool) error {
	// Convert the indirect sets to a JSON-encoded string
	indirectsJSON, err := json.Marshal(indirects)
	if err != nil {
		return err
	}

	// Save the indirect sets to the underlying storage
	// Replace this with your actual storage mechanism
	// For now, just print the indirect sets to the console
	println("Saving indirect sets for key:", key)
	println(string(indirectsJSON))

	return nil
}
