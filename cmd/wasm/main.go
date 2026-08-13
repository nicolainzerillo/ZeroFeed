//go:build js && wasm

package main

import (
	"encoding/hex"
	"sync"
	"syscall/js"

	"github.com/zerofeed/zerofeed/pkg/crypto"
	"github.com/zerofeed/zerofeed/pkg/feed"
	"github.com/zerofeed/zerofeed/pkg/protocol"
)

var (
	activePAKESub   *crypto.PAKEPeer
	activePAKEMutex sync.Mutex
)

func calculateSAS(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{"error": "keyHex argument required"}
	}
	keyBytes, err := hex.DecodeString(args[0].String())
	if err != nil {
		return map[string]interface{}{"error": "invalid hex key"}
	}
	hexSAS, emojiSAS := crypto.CalculateSAS(keyBytes)
	return map[string]interface{}{
		"hex":   hexSAS,
		"emoji": emojiSAS,
	}
}

func deriveKey(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return map[string]interface{}{"error": "passphrase and sessionID required"}
	}
	secret := []byte(args[0].String())
	sessionID, err := hex.DecodeString(args[1].String())
	if err != nil {
		sessionID = []byte(args[1].String())
	}

	key, err := crypto.DeriveKey(secret, sessionID)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	return hex.EncodeToString(key)
}

func encryptPayload(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return map[string]interface{}{"error": "keyHex and plaintext required"}
	}
	keyBytes, err := hex.DecodeString(args[0].String())
	if err != nil {
		return map[string]interface{}{"error": "invalid key hex"}
	}
	plaintext := []byte(args[1].String())
	var aad []byte
	if len(args) >= 3 && args[2].String() != "" {
		aad = []byte(args[2].String())
	}

	cipher, err := crypto.NewCipher(keyBytes)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}
	defer cipher.Close()

	ciphertext, nonce, err := cipher.Encrypt(plaintext, nil, aad)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	return map[string]interface{}{
		"ciphertextHex": hex.EncodeToString(ciphertext),
		"nonceHex":      hex.EncodeToString(nonce),
	}
}

func decryptPayload(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return map[string]interface{}{"error": "keyHex, ciphertextHex, nonceHex required"}
	}
	keyBytes, err := hex.DecodeString(args[0].String())
	if err != nil {
		return map[string]interface{}{"error": "invalid key hex"}
	}
	ciphertext, err := hex.DecodeString(args[1].String())
	if err != nil {
		return map[string]interface{}{"error": "invalid ciphertext hex"}
	}
	nonce, err := hex.DecodeString(args[2].String())
	if err != nil {
		return map[string]interface{}{"error": "invalid nonce hex"}
	}

	var aad []byte
	if len(args) >= 4 && args[3].String() != "" {
		var aErr error
		aad, aErr = hex.DecodeString(args[3].String())
		if aErr != nil {
			aad = []byte(args[3].String())
		}
	}

	cipher, err := crypto.NewCipher(keyBytes)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}
	defer cipher.Close()

	plaintext, err := cipher.Decrypt(ciphertext, nonce, aad)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	if unpadded, uErr := protocol.UnpadPayload(plaintext); uErr == nil {
		plaintext = unpadded
	}

	return hex.EncodeToString(plaintext)
}

func pakeInitSub(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{"error": "passphrase required"}
	}
	passphrase := []byte(args[0].String())

	subPeer, err := crypto.NewPAKESubscriber(passphrase)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	activePAKEMutex.Lock()
	if activePAKESub != nil {
		activePAKESub.Close()
	}
	activePAKESub = subPeer
	activePAKEMutex.Unlock()

	subMsg := subPeer.Bytes()
	return map[string]interface{}{
		"subWireMsgHex": hex.EncodeToString(subMsg),
	}
}

func pakeUpdateSub(this js.Value, args []js.Value) interface{} {
	activePAKEMutex.Lock()
	subPeer := activePAKESub
	activePAKEMutex.Unlock()

	if subPeer == nil {
		return map[string]interface{}{"error": "PAKE subscriber peer not initialized"}
	}
	if len(args) < 1 {
		return map[string]interface{}{"error": "pubWireMsgHex required"}
	}
	pubMsg, err := hex.DecodeString(args[0].String())
	if err != nil {
		return map[string]interface{}{"error": "invalid pubWireMsgHex"}
	}

	if len(pubMsg) < crypto.UniformWireMsgSize+60+32 {
		return map[string]interface{}{"error": "invalid PAKE response size or missing required key confirmation tag"}
	}

	pakeBytes := pubMsg[:crypto.UniformWireMsgSize]
	wrappedKeyPayload := pubMsg[crypto.UniformWireMsgSize : crypto.UniformWireMsgSize+60]
	pubConfirmTag := pubMsg[crypto.UniformWireMsgSize+60 : crypto.UniformWireMsgSize+60+32]

	if err := subPeer.Update(pakeBytes); err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	if err := subPeer.VerifyPeerConfirm(pubConfirmTag); err != nil {
		return map[string]interface{}{"error": "publisher key confirmation tag mismatch: " + err.Error()}
	}

	subConfirmTag, err := subPeer.ConfirmTag()
	if err != nil {
		return map[string]interface{}{"error": "failed to generate subscriber confirm tag: " + err.Error()}
	}

	p2pKey, err := subPeer.SessionKey()
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}
	defer crypto.ZeroBytes(p2pKey)

	masterSessionKey, err := crypto.UnwrapSessionKey(p2pKey, wrappedKeyPayload)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}
	defer crypto.ZeroBytes(masterSessionKey)

	sasHex, sasEmoji := crypto.CalculateSAS(masterSessionKey)

	return map[string]interface{}{
		"sessionKeyHex":    hex.EncodeToString(masterSessionKey),
		"subConfirmTagHex": hex.EncodeToString(subConfirmTag),
		"sasHex":           sasHex,
		"sasEmoji":         sasEmoji,
	}
}

func wipeAll(this js.Value, args []js.Value) interface{} {
	activePAKEMutex.Lock()
	if activePAKESub != nil {
		activePAKESub.Close()
		activePAKESub = nil
	}
	activePAKEMutex.Unlock()
	crypto.WipeAll()
	return true
}

func deriveSessionID(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{"error": "passphrase required"}
	}
	passphrase := []byte(args[0].String())
	sessionID := feed.DeriveSessionID(passphrase)
	return hex.EncodeToString(sessionID[:])
}

func ratchetKey(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return map[string]interface{}{"error": "currentKeyHex and saltHex required"}
	}
	currentKey, err := hex.DecodeString(args[0].String())
	if err != nil {
		return map[string]interface{}{"error": "invalid currentKeyHex"}
	}
	salt, err := hex.DecodeString(args[1].String())
	if err != nil {
		return map[string]interface{}{"error": "invalid saltHex"}
	}

	nextKey, err := crypto.RatchetKey(currentKey, salt)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	sasHex, sasEmoji := crypto.CalculateSAS(nextKey)
	return map[string]interface{}{
		"nextKeyHex": hex.EncodeToString(nextKey),
		"sasHex":     sasHex,
		"sasEmoji":   sasEmoji,
	}
}

func main() {
	c := make(chan struct{})

	js.Global().Set("zeroFeedCalculateSAS", js.FuncOf(calculateSAS))
	js.Global().Set("zeroFeedDeriveKey", js.FuncOf(deriveKey))
	js.Global().Set("zeroFeedDeriveSessionID", js.FuncOf(deriveSessionID))
	js.Global().Set("zeroFeedEncrypt", js.FuncOf(encryptPayload))
	js.Global().Set("zeroFeedDecrypt", js.FuncOf(decryptPayload))
	js.Global().Set("zeroFeedPAKEInitSub", js.FuncOf(pakeInitSub))
	js.Global().Set("zeroFeedPAKEUpdateSub", js.FuncOf(pakeUpdateSub))
	js.Global().Set("zeroFeedRatchetKey", js.FuncOf(ratchetKey))
	js.Global().Set("zeroFeedWipe", js.FuncOf(wipeAll))

	println("ZeroFeed WebAssembly (WASM) Engine v1.3.0 Initialized")
	<-c
}
