package agentlib

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"tunnel.local/crypto"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// registerOverWebSocketNew handles registration over an existing WebSocket connection
func (a *Agent) registerOverWebSocketNew(ctx context.Context, ws *websocket.Conn, cipher *crypto.StreamCipher) error {
	// Create registration frame
	regFrame := &RegisterFrame{
		Type:        "register",
		Protocol:    a.Protocol,
		Port:        a.Port,
		CustomURL:   a.CustomURL,
		UseRedirect: a.UseRedirect,
	}

	// Default to HTTP if not specified
	if regFrame.Protocol == "" {
		regFrame.Protocol = "http"
	}

	// Encrypt and send registration request
	regData, err := json.Marshal(regFrame)
	if err != nil {
		return fmt.Errorf("failed to marshal registration: %w", err)
	}

	encryptedRegData, err := cipher.Encrypt(regData)
	if err != nil {
		return fmt.Errorf("failed to encrypt registration: %w", err)
	}

	if err := ws.Write(ctx, websocket.MessageBinary, encryptedRegData); err != nil {
		return fmt.Errorf("failed to send registration: %w", err)
	}

	// Wait for registration response
	_, responseData, err := ws.Read(ctx)
	if err != nil {
		return fmt.Errorf("failed to read registration response: %w", err)
	}

	// Decrypt response
	decryptedResponse, err := cipher.Decrypt(responseData)
	if err != nil {
		return fmt.Errorf("failed to decrypt registration response: %w", err)
	}

	var regResp RegisterResponseFrame
	if err := json.Unmarshal(decryptedResponse, &regResp); err != nil {
		return fmt.Errorf("failed to parse registration response: %w", err)
	}

	if regResp.Type != "register_response" {
		return fmt.Errorf("unexpected response type: %s", regResp.Type)
	}

	if !regResp.Success {
		return fmt.Errorf("registration failed: %s", regResp.Error)
	}

	// Store only ID and Secret from server response
	// Agent configuration (CustomURL, UseRedirect, Protocol, Port) should remain
	// as originally provided to avoid sending back server-formatted values
	a.ID = regResp.ID
	a.Secret = regResp.Secret

	// Initialize debug logging now that we have tunnel ID
	if a.DebugLog {
		log.Printf("AGENT DEBUG: Debug logging enabled for tunnel ID: %s", a.ID)
	}

	// Log the URLs from server response
	fmt.Println("  Public URL:", regResp.PublicURL)
	if regResp.CustomURL != "" {
		fmt.Println("  Custom URL:", regResp.CustomURL)
		if regResp.UseRedirect {
			fmt.Println("  SPA Redirection: Enabled")
		}
	}

	return nil
}

// registerNew handles initial registration process
func (a *Agent) registerNew() (*RegisterResp, error) {
	// Create WebSocket connection for registration (without existing credentials)
	wsURL := strings.Replace(a.ServerURL, "http", "ws", 1) + "/__ws__"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect for registration: %w", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "registration complete")

	// Complete handshake first
	var handshake HandshakeFrame
	err = wsjson.Read(ctx, conn, &handshake)
	if err != nil {
		return nil, fmt.Errorf("failed to read handshake: %w", err)
	}

	// Send handshake ACK
	handshakeResp := map[string]interface{}{
		"type": "handshake",
		"ack":  true,
	}
	err = wsjson.Write(ctx, conn, handshakeResp)
	if err != nil {
		return nil, fmt.Errorf("failed to send handshake ACK: %w", err)
	}

	// Create cipher for registration
	salt, err := base64.StdEncoding.DecodeString(handshake.Salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	// Use the well-known temporary secret that the server expects for new registrations
	tempSecretString := "temp_handshake_secret_for_registration"
	masterSecret := sha256.Sum256([]byte(tempSecretString))
	cipher, err := crypto.NewStreamCipher(masterSecret[:], salt, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create registration frame
	regFrame := &RegisterFrame{
		Type:        "register",
		Protocol:    a.Protocol,
		Port:        a.Port,
		CustomURL:   a.CustomURL,
		UseRedirect: a.UseRedirect,
	}

	// Default to HTTP if not specified
	if regFrame.Protocol == "" {
		regFrame.Protocol = "http"
	}

	// Encrypt and send registration request
	regData, err := json.Marshal(regFrame)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration: %w", err)
	}

	encryptedRegData, err := cipher.Encrypt(regData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt registration: %w", err)
	}

	if err := conn.Write(ctx, websocket.MessageBinary, encryptedRegData); err != nil {
		return nil, fmt.Errorf("failed to send registration: %w", err)
	}

	// Wait for registration response
	_, responseData, err := conn.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read registration response: %w", err)
	}

	// Decrypt response
	decryptedResponse, err := cipher.Decrypt(responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt registration response: %w", err)
	}

	var regResp RegisterResponseFrame
	if err := json.Unmarshal(decryptedResponse, &regResp); err != nil {
		return nil, fmt.Errorf("failed to parse registration response: %w", err)
	}

	if regResp.Type != "register_response" {
		return nil, fmt.Errorf("unexpected response type: %s", regResp.Type)
	}

	if !regResp.Success {
		return nil, fmt.Errorf("registration failed: %s", regResp.Error)
	}

	// Convert to RegisterResp format for compatibility
	return &RegisterResp{
		ID:          regResp.ID,
		Secret:      regResp.Secret,
		PublicURL:   regResp.PublicURL,
		CustomURL:   regResp.CustomURL,
		UseRedirect: regResp.UseRedirect,
	}, nil
}

// mustJSONNew is a utility function for marshaling to JSON
func mustJSONNew(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
