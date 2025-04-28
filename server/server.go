package server

import (
	"crypto/rsa"
	"encoding/json"
	"os"

	"github.com/google/uuid"

	"access_utils"
	"auth_utils"
	"crypto_utils"
	"encoding/hex"
	. "types"
)

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey

var name string
var kvstore map[string]KeyValue
var Requests chan NetworkData
var Responses chan NetworkData

// Session management
var session *auth_utils.SessionData
var BindingTable map[string]BindingTableData

func init() {
	privateKey = crypto_utils.NewPrivateKey()
	publicKey = &privateKey.PublicKey
	publicKeyBytes := crypto_utils.PublicKeyToBytes(publicKey)
	if err := os.WriteFile("SERVER_PUBLICKEY", publicKeyBytes, 0666); err != nil {
		panic(err)
	}

	name = uuid.NewString()
	kvstore = make(map[string]KeyValue)
	BindingTable = make(map[string]BindingTableData)
	Requests = make(chan NetworkData)
	Responses = make(chan NetworkData)

	session = auth_utils.InitSessionData(name, privateKey)

	go receiveThenSend()
}

func receiveThenSend() {
	defer close(Responses)

	for request := range Requests {
		Responses <- process(request)
	}
}

// Process incoming requests
func process(requestData NetworkData) NetworkData {
	var responseBytes []byte

	// First try to unmarshal as an AuthRequest (for login or register)
	var authRequest AuthRequest
	err := json.Unmarshal(requestData.Payload, &authRequest)

	if err == nil && len(authRequest.SharedKeyEncrypted) > 0 && len(authRequest.MessageEncrypted) > 0 {
		// This is an authentication request (could be login or register)
		var response Response
		var authResponse AuthResponse

		// Try to determine if it's a register request by decrypting first
		sharedKey, keyErr := crypto_utils.DecryptPK(authRequest.SharedKeyEncrypted, privateKey)
		if keyErr == nil {
			msgBytes, msgErr := crypto_utils.DecryptSK(authRequest.MessageEncrypted, sharedKey)
			if msgErr == nil {
				var content AuthEncryptedContent
				if json.Unmarshal(msgBytes, &content) == nil {
					var innerMsg InnerAuthMessage
					if json.Unmarshal(content.InnerMessage, &innerMsg) == nil {
						if innerMsg.Op == string(rune(REGISTER)) {
							// This is a register request
							processRegisterAuth(&authRequest, requestData.Name, &response)
							responseBytes, _ = json.Marshal(response)
							return NetworkData{Payload: responseBytes, Name: name}
						}
					}
				}
			}
		}

		// If not a register request or couldn't determine, process as login
		processAuthLogin(&authRequest, requestData.Name, &response, &authResponse)

		responseBytes, _ = json.Marshal(authResponse)
		return NetworkData{Payload: responseBytes, Name: name}
	}

	// Check if it's a secure operation request
	if session.Active {
		var secureMessage SecureMessage
		if err := json.Unmarshal(requestData.Payload, &secureMessage); err == nil {
			// This is a secure request during an active session
			processSecureRequest(&secureMessage, &responseBytes)
			return NetworkData{Payload: responseBytes, Name: name}
		}
	}

	// Not an auth request or secure request, try as a regular request
	var request Request
	var response Response

	if err := json.Unmarshal(requestData.Payload, &request); err != nil {
		response.Status = FAIL
		responseBytes, _ = json.Marshal(response)
		return NetworkData{Payload: responseBytes, Name: name}
	}

	// Regular operation
	doOp(&request, &response)

	responseBytes, _ = json.Marshal(response)
	return NetworkData{Payload: responseBytes, Name: name}
}

// Process a secure request during an active session
func processSecureRequest(secureMessage *SecureMessage, responseBytes *[]byte) {
	// Default failure response
	response := Response{Status: FAIL, Uid: session.UserID}
	secureResponseMessage, err := auth_utils.EncryptResponse(&response, session)
	if err != nil {
		secureResponseBytes, _ := json.Marshal(secureResponseMessage)
		*responseBytes = secureResponseBytes
		return
	}

	// 1. Decrypt and verify the secure request
	request, valid, err := auth_utils.DecryptRequest(secureMessage, session)
	if err != nil || !valid {
		secureResponseBytes, _ := json.Marshal(secureResponseMessage)
		*responseBytes = secureResponseBytes
		return
	}

	// 2. Process the regular operation
	doOp(request, &response)
	// 3. Encrypt the response
	secureResponseMessage, err = auth_utils.EncryptResponse(&response, session)
	if err != nil {
		secureResponseBytes, _ := json.Marshal(secureResponseMessage)
		*responseBytes = secureResponseBytes
		return
	}

	// 4. Marshal the secure response
	secureResponseBytes, _ := json.Marshal(secureResponseMessage)
	*responseBytes = secureResponseBytes

	// 5. Special handling for logout
	if request.Op == LOGOUT && response.Status == OK {
		session.Active = false
		session.SharedKey = nil
		session.UserID = ""
		session.VerificationKey = nil
		// Clear nonce map on logout
		if session.SeenNonces != nil {
			session.SeenNonces = make(map[string]bool)
		}
	}
}

func processAuthLogin(authRequest *AuthRequest, clientName string, response *Response, authResponse *AuthResponse) {
	response.Status = FAIL

	if session.Active {
		response.Status = FAIL
		return
	}

	// Add validation for empty or malformed authRequest
	if authRequest == nil || len(authRequest.SharedKeyEncrypted) == 0 || len(authRequest.MessageEncrypted) < 12 {
		response.Status = FAIL
		return
	}

	// 1. Decrypt shared key
	sharedKey, err := crypto_utils.DecryptPK(authRequest.SharedKeyEncrypted, privateKey)
	if err != nil {
		response.Status = FAIL
		return
	}

	// Make sure we have a valid shared key
	if len(sharedKey) == 0 {
		response.Status = FAIL
		return
	}

	// 2. Verify and decrypt client message
	// First, we need to parse the client verification key
	// Since we don't have it yet, we'll need to do this in two phases

	// a) First, decrypt the client's message
	decryptedBytes, err := crypto_utils.DecryptSK(authRequest.MessageEncrypted, sharedKey)
	if err != nil {
		response.Status = FAIL
		return
	}

	// b) Parse the encrypted content to get the client verification key
	var encryptedContent AuthEncryptedContent
	if err := json.Unmarshal(decryptedBytes, &encryptedContent); err != nil {
		response.Status = FAIL
		return
	}

	// c) Parse the inner message to get the client verification key
	var innerClientMessage InnerAuthMessage
	if err := json.Unmarshal(encryptedContent.InnerMessage, &innerClientMessage); err != nil {
		response.Status = FAIL
		return
	}

	// d) Parse the client verification key
	clientVerificationKey, err := crypto_utils.BytesToPublicKey(innerClientMessage.VerificationKey)
	if err != nil {
		response.Status = FAIL
		return
	}

	// e) Now verify the signature
	validSignature := crypto_utils.Verify(
		encryptedContent.Signature,
		crypto_utils.Hash(encryptedContent.InnerMessage),
		clientVerificationKey,
	)

	if !validSignature {
		response.Status = FAIL
		return
	}

	// f) Verify time of day (freshness)
	messageTOD := crypto_utils.BytesToTod(innerClientMessage.TimeOfDay)
	currentTOD := crypto_utils.ReadClock()

	bindingData, exists := BindingTable[innerClientMessage.Uid]
	if exists {
		recentLoginTime := bindingData.RecentLoginTime

		// Message time should be after login time and before current time
		if !(recentLoginTime.Before(messageTOD) && messageTOD.Before(currentTOD)) {
			response.Status = FAIL
			return
		}

		// Verify password if this is a LOGIN operation
		if innerClientMessage.Op == string(rune(LOGIN)) {
			// Verify password using stored hash and salt
			passwordHash := crypto_utils.HashWithSalt(innerClientMessage.Password, bindingData.Salt)
			if !crypto_utils.CompareHashes(passwordHash, bindingData.PasswordHash) {
				response.Status = FAIL
				return
			}
		}
	} else {
		response.Status = FAIL
		return
	}

	// For new users (first login), we only check that the message time is before current time
	if !exists && !messageTOD.Before(currentTOD) {
		response.Status = FAIL
		return
	}

	// g) Check if nonce has been seen before
	nonceBytes, err := hex.DecodeString(innerClientMessage.Nonce)
	if err != nil {
		response.Status = FAIL
		return
	}
	if !auth_utils.CheckAndRecordAuthNonce(nonceBytes) {
		response.Status = FAIL
		return
	}

	// h) Verify the client's name matches
	if innerClientMessage.Name != clientName {
		response.Status = FAIL
		return
	}

	// 3. Create server's auth message
	serverAuthContentBytes, err := auth_utils.CreateAuthMessage(
		name,
		innerClientMessage.Uid,
		string(rune(LOGIN)),
		crypto_utils.PublicKeyToBytes(publicKey),
		privateKey,
	)

	if err != nil || len(serverAuthContentBytes) == 0 {
		response.Status = FAIL
		return
	}

	// 4. Encrypt the server's auth content with shared key
	encryptedServerAuthBytes := auth_utils.EncryptAuthMessage(serverAuthContentBytes, sharedKey)

	// Validate encryption was successful and the result is at least 12 bytes (for IV)
	if len(encryptedServerAuthBytes) < 12 {
		response.Status = FAIL
		return
	}

	// 5. Create auth response
	*authResponse = AuthResponse{
		MessageEncrypted: encryptedServerAuthBytes,
	}

	// 6. Update session state
	session.Active = true
	session.SharedKey = sharedKey
	session.UserID = innerClientMessage.Uid
	session.VerificationKey = clientVerificationKey

	// 7. Update binding table
	BindingTable[session.UserID] = BindingTableData{
		ClientVerificationKey: clientVerificationKey,
		RecentLoginTime:       crypto_utils.ReadClock(),
		PasswordHash:          bindingData.PasswordHash,
		Salt:                  bindingData.Salt,
	}

	// 8. Update response status
	response.Status = OK
	response.Uid = session.UserID
}

// Process registration auth request
func processRegisterAuth(authRequest *AuthRequest, clientName string, response *Response) {
	response.Status = FAIL

	// 1. Decrypt shared key
	sharedKey, err := crypto_utils.DecryptPK(authRequest.SharedKeyEncrypted, privateKey)
	if err != nil {
		return
	}

	// 2. Decrypt the client's message
	decryptedBytes, err := crypto_utils.DecryptSK(authRequest.MessageEncrypted, sharedKey)
	if err != nil {
		return
	}

	// 3. Parse the encrypted content
	var encryptedContent AuthEncryptedContent
	if err := json.Unmarshal(decryptedBytes, &encryptedContent); err != nil {
		return
	}

	// 4. Parse the inner message
	var innerClientMessage InnerAuthMessage
	if err := json.Unmarshal(encryptedContent.InnerMessage, &innerClientMessage); err != nil {
		return
	}

	// 5. Parse the client verification key
	clientVerificationKey, err := crypto_utils.BytesToPublicKey(innerClientMessage.VerificationKey)
	if err != nil {
		return
	}

	// 6. Verify the signature
	validSignature := crypto_utils.Verify(
		encryptedContent.Signature,
		crypto_utils.Hash(encryptedContent.InnerMessage),
		clientVerificationKey,
	)

	if !validSignature {
		return
	}

	// 7. Verify the client's name matches
	if innerClientMessage.Name != clientName {
		return
	}

	// 8. Check if operation is REGISTER
	if innerClientMessage.Op != string(rune(REGISTER)) {
		return
	}

	// 9. Check if user already exists
	if _, exists := BindingTable[innerClientMessage.Uid]; exists {
		return
	}

	// 10. Check if nonce has been seen before
	nonceBytes, err := hex.DecodeString(innerClientMessage.Nonce)
	if err != nil {
		return
	}
	if !auth_utils.CheckAndRecordAuthNonce(nonceBytes) {
		return
	}

	// 11. Generate salt and hash password
	salt := crypto_utils.GenerateRandomBytes(32)
	passwordHash := crypto_utils.HashWithSalt(innerClientMessage.Password, salt)

	// 12. Store in binding table
	BindingTable[innerClientMessage.Uid] = BindingTableData{
		ClientVerificationKey: clientVerificationKey,
		PasswordHash:          passwordHash,
		Salt:                  salt,
		RecentLoginTime:       crypto_utils.BytesToTod(innerClientMessage.TimeOfDay),
	}

	// 13. Update response
	response.Status = OK
	response.Uid = innerClientMessage.Uid
}

// Regular operation handler
func doOp(request *Request, response *Response) {
	response.Status = FAIL
	response.Uid = session.UserID

	if session.Active {
		switch request.Op {
		case NOOP:
			// NOTHING
		case CREATE:
			doCreate(request, response)
		case DELETE:
			doDelete(request, response)
		case READ:
			doReadVal(request, response)
		case WRITE:
			doWriteVal(request, response)
		case COPY:
			doCopy(request, response)
		case LOGOUT:
			doLogout(request, response)
		case REGISTER:
			doRegister(request, response)
		case CHANGE_PASS:
			doChangePass(request, response)
		case MODACL:
			doModAcl(request, response)
		case REVACL:
			doRevAcl(request, response)
		default:
			// struct already default initialized to FAIL status
		}
	} else {
		// Only login is allowed when no session is active
		if request.Op == LOGIN {
			// Regular login is not supported, only secure authentication
			// Keep response.Status as FAIL
		}
	}
}

// Input: key k, value v, metaval m. Returns a response.
// Sets the value and metaval for key k in the
// key-value store to value v and metavalue m.
func doCreate(request *Request, response *Response) {
	if _, exists := kvstore[request.Key]; exists {
		response.Status = FAIL
		return
	}

	keyValue := KeyValue{
		Val:       request.Val,
		Owner:     session.UserID,
		Readers:   make(map[string]bool),
		Writers:   make(map[string]bool),
		Copyfroms: make(map[string]bool),
		Copytos:   make(map[string]bool),
		Indirects: make(map[string]bool),
	}

	// Initialize from request
	for _, u := range request.Readers {
		keyValue.Readers[u] = true
	}
	for _, u := range request.Writers {
		keyValue.Writers[u] = true
	}
	for _, u := range request.Copyfroms {
		keyValue.Copyfroms[u] = true
	}
	for _, u := range request.Copytos {
		keyValue.Copytos[u] = true
	}
	for _, k := range request.Indirects {
		if _, exists := kvstore[k]; !exists {
			response.Status = FAIL
			return
		}
		keyValue.Indirects[k] = true
	}

	kvstore[request.Key] = keyValue
	response.Status = OK
}

// Input: key k. Returns a response. Deletes key from
// key-value store. If key does not exist then take no
// action.
func doDelete(request *Request, response *Response) {

	// TODO: add condition to allow only k.owner to delete the key.
	// Check if the user is the owner of the key
	if kvstore[request.Key].Owner != session.UserID {
		response.Status = FAIL
		return
	}
	if _, ok := kvstore[request.Key]; ok {
		delete(kvstore, request.Key)
		response.Status = OK
	}
}

// Input: key k. Returns a response with the value
// associated with key. If key does not exist
// then status is FAIL.
func doReadVal(request *Request, response *Response) {

	// TODO: add condition to allow only people in k.readers set to perform this op
	// check access_utils.isInReaderSet(session.Uid) then perform
	if !access_utils.IsInReaderSet(request.Key, session.UserID, kvstore) {
		response.Status = FAIL
		return
	}
	if kv, ok := kvstore[request.Key]; ok {
		response.Val = kv.Val
		response.Status = OK
	}
}

// Input: key k and value v. Returns a response.
// Change value in the key-value store associated
// with key k to value v. If key does not exist
// then status is FAIL.
func doWriteVal(request *Request, response *Response) {

	// TODO: add condition to allow only people in k.writers set to perform this op
	// check access_utils.isInWriterSet(session.Uid) then perform
	if !access_utils.IsInWriterSet(request.Key, session.UserID, kvstore) {
		response.Status = FAIL
		return
	}

	if existingKeyValue, ok := kvstore[request.Key]; ok {

		updatedKeyValue := existingKeyValue

		updatedKeyValue.Val = request.Val

		kvstore[request.Key] = updatedKeyValue
		response.Status = OK
	}
}

// Copy function - copies the value from src_key to dst_key
// Both keys must exist for the operation to succeed
// TODO: to perform this we need to check
// 1. person copying is present in k.copyfroms of src key
// 2. person copying is present in k.copytos of dst key
// check access_utils.isInCopyToSet(session.Uid) && access_utils.isInCopyFromSet(session.Uid)

func doCopy(request *Request, response *Response) {
	if _, srcOk := kvstore[request.Src_key]; !srcOk {
		response.Status = FAIL
		return
	}
	if _, dstOk := kvstore[request.Dst_key]; !dstOk {
		response.Status = FAIL
		return
	}

	if !access_utils.IsInCopyFromSet(request.Src_key, session.UserID, kvstore) ||
		!access_utils.IsInCopyToSet(request.Dst_key, session.UserID, kvstore) {
		response.Status = FAIL
		return
	}

	// Copy only the value, not the access control sets
	kvstore[request.Dst_key] = KeyValue{
		Val:       kvstore[request.Src_key].Val,
		Owner:     kvstore[request.Dst_key].Owner,
		Readers:   kvstore[request.Dst_key].Readers,
		Writers:   kvstore[request.Dst_key].Writers,
		Copyfroms: kvstore[request.Dst_key].Copyfroms,
		Copytos:   kvstore[request.Dst_key].Copytos,
		Indirects: kvstore[request.Dst_key].Indirects,
	}
	response.Status = OK
}

// When the session is active allow logout
func doLogout(request *Request, response *Response) {
	if session.Active {
		response.Status = OK
		response.Uid = session.UserID

		// Clear client key from binding table
		if data, exists := BindingTable[session.UserID]; exists {
			data.ClientVerificationKey = nil
			BindingTable[session.UserID] = data
		}
	}
}

func doRegister(request *Request, response *Response) {
	// 1. Check if user already exists in the BindingTable
	if _, exists := BindingTable[request.Uid]; exists {
		response.Status = FAIL
		return
	}
	if session.Active {
		response.Status = FAIL
		return
	}
	// 2. Generate random salt
	salt := crypto_utils.GenerateRandomBytes(32)

	// 3. Hash the password with salt using work factor
	passwordHash := crypto_utils.HashWithSalt(request.Pass, salt)

	// 4. Store in binding table using existing BindingTableData type
	BindingTable[request.Uid] = BindingTableData{
		ClientVerificationKey: nil, // Will be updated on login
		PasswordHash:          passwordHash,
		Salt:                  salt,
		RecentLoginTime:       crypto_utils.ReadClock(),
	}

	// 5. Set response status
	response.Status = OK
	response.Uid = request.Uid
}

func doChangePass(request *Request, response *Response) {
	// 1. Retrieve user data from binding table
	userData, exists := BindingTable[session.UserID]
	if !exists {
		response.Status = FAIL
		return
	}

	// 2. Verify current password
	oldPassHash := crypto_utils.HashWithSalt(request.Old_pass, userData.Salt)

	if !crypto_utils.CompareHashes(oldPassHash, userData.PasswordHash) {
		response.Status = FAIL
		return
	}

	// 3. If verification succeeds, update password
	// Generate new salt
	newSalt := crypto_utils.GenerateRandomBytes(32)

	// Compute new password hash
	newPassHash := crypto_utils.HashWithSalt(request.New_pass, newSalt)

	// Update binding table with new password hash and salt
	userData.PasswordHash = newPassHash
	userData.Salt = newSalt

	// Store updated user data
	BindingTable[session.UserID] = userData

	// 4. Set response status
	response.Status = OK
	response.Uid = session.UserID
}

// only allow owners to perform these operations
// if particular set is not passed dont do anything with that
// if [] is passed for some operation reset that particular op set to empty
func doModAcl(request *Request, response *Response) {
	keyValue, exists := kvstore[request.Key]
	if !exists || keyValue.Owner != session.UserID {
		response.Status = FAIL
		return
	}

	// nil → no change, [] → reset to empty
	if request.Readers != nil {
		keyValue.Readers = make(map[string]bool)
		for _, u := range request.Readers {
			keyValue.Readers[u] = true
		}
	}
	if request.Writers != nil {
		keyValue.Writers = make(map[string]bool)
		for _, u := range request.Writers {
			keyValue.Writers[u] = true
		}
	}
	if request.Copyfroms != nil {
		keyValue.Copyfroms = make(map[string]bool)
		for _, u := range request.Copyfroms {
			keyValue.Copyfroms[u] = true
		}
	}
	if request.Copytos != nil {
		keyValue.Copytos = make(map[string]bool)
		for _, u := range request.Copytos {
			keyValue.Copytos[u] = true
		}
	}
	if request.Indirects != nil {
		keyValue.Indirects = make(map[string]bool)
		for _, k := range request.Indirects {
			keyValue.Indirects[k] = true
		}
	}

	kvstore[request.Key] = keyValue
	response.Status = OK
}

// Input: request *Request, response *Response
// Helps owner review all the permissions of kv store
// Returns unions of the direct access control sets and indirect sets
func doRevAcl(request *Request, response *Response) {
	keyValue, exists := kvstore[request.Key]
	if !exists || keyValue.Owner != session.UserID {
		response.Status = FAIL
		return
	}

	// Direct sets
	response.Readers = mapKeysToSlice(keyValue.Readers)
	response.Writers = mapKeysToSlice(keyValue.Writers)
	response.Copytos = mapKeysToSlice(keyValue.Copytos)
	response.Copyfroms = mapKeysToSlice(keyValue.Copyfroms)
	response.Indirects = mapKeysToSlice(keyValue.Indirects)

	// Effective sets (with indirects)
	effectiveReaders := access_utils.GetEffectiveReaderSet(request.Key, kvstore)
	effectiveWriters := access_utils.GetEffectiveWriterSet(request.Key, kvstore)
	effectiveCopyfroms := access_utils.GetEffectiveCopyFromSet(request.Key, kvstore)
	effectiveCopytos := access_utils.GetEffectiveCopyToSet(request.Key, kvstore)

	response.R_k = mapKeysToSlice(effectiveReaders)
	response.W_k = mapKeysToSlice(effectiveWriters)
	response.C_Src_k = mapKeysToSlice(effectiveCopyfroms)
	response.C_Dst_k = mapKeysToSlice(effectiveCopytos)

	response.Status = OK
}

func mapKeysToSlice(m map[string]bool) []string {
	slice := make([]string, 0, len(m))
	for k := range m {
		slice = append(slice, k)
	}
	return slice
}
