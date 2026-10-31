// IDORaider Vulnerable Lab Server.
//
// A lightweight, zero-dependency mock API that simulates real-world BOLA/IDOR
// vulnerabilities and properly protected endpoints. Used for local training,
// automated CI testing, and demonstrating IDORaider's dual-token detection engine.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

type response map[string]interface{}

func main() {
	port := flag.Int("port", 8888, "Port to listen on")
	flag.Parse()

	mux := http.NewServeMux()

	// 1. User Profiles Endpoint (VULNERABLE: Any token can access any profile)
	mux.HandleFunc("/api/v1/users/", func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, response{"error": "Authentication required"})
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
		switch id {
		case "1":
			writeJSON(w, http.StatusOK, response{
				"id":       1,
				"username": "alice",
				"email":    "alice@target.corp",
				"role":     "member",
				"secret":   "FLAG{bola_user_profile_leak}",
			})
		case "2":
			writeJSON(w, http.StatusOK, response{
				"id":       2,
				"username": "bob",
				"email":    "bob@target.corp",
				"role":     "member",
			})
		case "123":
			writeJSON(w, http.StatusOK, response{
				"id":       123,
				"username": "charlie_vip",
				"email":    "charlie@vip.corp",
				"balance":  99450,
			})
		default:
			writeJSON(w, http.StatusNotFound, response{"error": "User not found"})
		}
	})

	// 2. Invoices Endpoint (VULNERABLE: Billing records accessible across tenants)
	mux.HandleFunc("/api/v1/invoices/", func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, response{"error": "Authentication required"})
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/invoices/")
		switch id {
		case "89", "90":
			writeJSON(w, http.StatusOK, response{
				"invoice_id": id,
				"amount":     15400.00,
				"total":      15400.00,
				"payment":    "completed",
				"card_last4": "4242",
				"client":     "Alice Enterprise Ltd",
			})
		default:
			writeJSON(w, http.StatusNotFound, response{"error": "Invoice not found"})
		}
	})

	// 3. Admin Endpoint (PROPERLY PROTECTED: Only admin token allowed)
	mux.HandleFunc("/api/v1/admin/", func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, response{"error": "Authentication required"})
			return
		}
		if token != "admin_secret_token" {
			writeJSON(w, http.StatusForbidden, response{"error": "Forbidden: Requires administrator privilege"})
			return
		}
		writeJSON(w, http.StatusOK, response{
			"status":    "active",
			"dashboard": "System Administration Console",
			"settings":  "Internal Configuration",
		})
	})

	// 4. Orders Endpoint (VULNERABLE: Orders readable by ID)
	mux.HandleFunc("/api/v1/orders/", func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, response{"error": "Authentication required"})
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/orders/")
		if id == "457" || id == "458" {
			writeJSON(w, http.StatusOK, response{
				"order_id":         id,
				"shipping_address": "742 Evergreen Terrace",
				"customer_email":   "alice@private.com",
				"total":            249.99,
			})
			return
		}
		writeJSON(w, http.StatusNotFound, response{"error": "Order not found"})
	})

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	fmt.Println(`
   ___ ___   ___  ___       _     _             _           _     
  |_ _|   \ / _ \| _ \__ _ (_) __| |___ _ _ ___| |   __ _ | |__  
   | || |) | (_) |   / _` + "`" + ` || |/ _` + "`" + ` / -_) '_|___| |__/ _` + "`" + ` || '_ \ 
  |___|___/ \___/|_|_\__,_||_|\__,_\___|_|   |____\__,_||_.__/ 
  `)
	fmt.Println("  IDORaider Vulnerable BOLA Lab API")
	fmt.Printf("  Listening on: http://%s\n\n", addr)
	fmt.Println("  Test Accounts:")
	fmt.Println("    - Alice (Resource Owner) : token_alice")
	fmt.Println("    - Bob   (Attacker Replay): token_bob")
	fmt.Println("    - Admin (Privileged)     : admin_secret_token")
	fmt.Println("\n  Ready to test! In a second terminal, run:")
	fmt.Printf("    .\\idoraider.exe -u http://%s -t templates/ --token \"token_alice\" --secondary-token \"token_bob\"\n\n", addr)

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

func extractToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return strings.TrimSpace(parts[1])
	}
	return strings.TrimSpace(auth)
}

func writeJSON(w http.ResponseWriter, status int, data response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

