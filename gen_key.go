package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func main() {
	// Generate a random 32-byte key
	keyBytes := make([]byte, 32)
	_, err := rand.Read(keyBytes)
	if err != nil {
		panic(err)
	}
	
	// Convert to hex string (64 chars)
	key := hex.EncodeToString(keyBytes)
	
	// Hash it
	h := sha256.Sum256([]byte(key))
	keyHash := hex.EncodeToString(h[:])
	
	fmt.Println("===== LIFETIME API KEY =====")
	fmt.Println("Key (use this):")
	fmt.Println(key)
	fmt.Println()
	fmt.Println("Key Hash (SHA-256):")
	fmt.Println(keyHash)
	fmt.Println()
	fmt.Println("===== INSERT SQL =====")
	fmt.Printf("INSERT INTO api_keys (key, status, tier, scope, label, created_at, expires_at, max_requests, request_count) VALUES ('%s', 'active', 'staff', 'valo', 'Lifetime Emulator Key', datetime('now'), NULL, NULL, 0);\n", keyHash)
}
