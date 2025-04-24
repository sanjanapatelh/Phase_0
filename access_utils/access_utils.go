package access_utils

import (
	. "types"
)

// getFieldMap is a helper function that returns the appropriate field map based on the field name
func getFieldMap(keyValue KeyValue, fieldName string) map[string]bool {
	switch fieldName {
	case "Readers":
		return keyValue.Readers
	case "Writers":
		return keyValue.Writers
	case "Copytos":
		return keyValue.Copytos
	case "Copyfroms":
		return keyValue.Copyfroms
	default:
		return nil
	}
}

// IsInSet is a generic function that checks if a user is in a specific set
// It handles circular dependencies by tracking visited keys
func IsInSet(key string, uid string, kvstore map[string]KeyValue, fieldName string, visited map[string]bool) bool {
	// Check for circular dependencies
	if visited == nil {
		visited = make(map[string]bool)
	}
	if visited[key] {
		return false // Break circular dependency
	}
	visited[key] = true

	// Get the key-value pair from the store
	keyValue, ok := kvstore[key]
	if !ok {
		return false
	}

	// Check if the user is in the specified set
	fieldMap := getFieldMap(keyValue, fieldName)
	if _, ok := fieldMap[uid]; ok {
		return true
	}

	// Check if the user is in any of the indirect sets
	for indirect := range keyValue.Indirects {
		if _, ok := kvstore[indirect]; ok {
			if IsInSet(indirect, uid, kvstore, fieldName, visited) {
				return true
			}
		}
	}

	return false
}

// Public wrapper functions that initialize the visited map
func IsInReaderSet(key string, uid string, kvstore map[string]KeyValue) bool {
	return IsInSet(key, uid, kvstore, "Readers", nil)
}

func IsInWriterSet(key string, uid string, kvstore map[string]KeyValue) bool {
	return IsInSet(key, uid, kvstore, "Writers", nil)
}

func IsInCopyToSet(key string, uid string, kvstore map[string]KeyValue) bool {
	return IsInSet(key, uid, kvstore, "Copytos", nil)
}

func IsInCopyFromSet(key string, uid string, kvstore map[string]KeyValue) bool {
	return IsInSet(key, uid, kvstore, "Copyfroms", nil)
}

// GetEffectiveSet is a generic function that returns the effective set for a given field
// It also handles circular dependencies by tracking visited keys
func GetEffectiveSet(key string, kvstore map[string]KeyValue, fieldName string, visited map[string]bool) map[string]bool {
	result := make(map[string]bool)
	
	// Check for circular dependencies
	if visited == nil {
		visited = make(map[string]bool)
	}
	if visited[key] {
		return result // Break circular dependency
	}
	visited[key] = true

	// If key exists, add its field set to the result
	if v, ok := kvstore[key]; ok {
		fieldMap := getFieldMap(v, fieldName)
		for u := range fieldMap {
			result[u] = true
		}

		// Add the field sets of all the indirect sets to the result
		for indirect := range v.Indirects {
			if _, ok := kvstore[indirect]; ok {
				for u := range GetEffectiveSet(indirect, kvstore, fieldName, visited) {
					result[u] = true
				}
			}
		}
	}

	return result
}

// Public wrapper functions that initialize the visited map
func GetEffectiveReaderSet(key string, kvstore map[string]KeyValue) map[string]bool {
	return GetEffectiveSet(key, kvstore, "Readers", nil)
}

func GetEffectiveWriterSet(key string, kvstore map[string]KeyValue) map[string]bool {
	return GetEffectiveSet(key, kvstore, "Writers", nil)
}

func GetEffectiveCopyFromSet(key string, kvstore map[string]KeyValue) map[string]bool {
	return GetEffectiveSet(key, kvstore, "Copyfroms", nil)
}

func GetEffectiveCopyToSet(key string, kvstore map[string]KeyValue) map[string]bool {
	return GetEffectiveSet(key, kvstore, "Copytos", nil)
}