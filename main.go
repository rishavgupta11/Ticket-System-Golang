package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("super-secret-intern-key") // In production, load this from .env

// --- Models ---
type User struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
}

type Ticket struct {
	ID          string `json:"id"`
	UserID      string `json:"user_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Status      string `json:"status"` // open, in_progress, closed
}

// --- In-Memory Store ---
type Store struct {
	users         map[string]User
	tickets       map[string]Ticket
	mu            sync.RWMutex
	ticketCounter int
	userCounter   int
}

var db = &Store{
	users:   make(map[string]User),
	tickets: make(map[string]Ticket),
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	return false
}

func ticketIDFromPath(r *http.Request) string {
	id := r.PathValue("id")
	if id != "" {
		return id
	}
	path := strings.TrimPrefix(r.URL.Path, "/tickets/")
	return strings.TrimSuffix(path, "/status")
}

// --- Middleware ---
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "missing or invalid authorization token")
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}

		// Pass the UserID in the header for downstream handlers
		r.Header.Set("X-User-ID", claims.Subject)
		next.ServeHTTP(w, r)
	}
}

// --- Handlers ---

// GET /health
func healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /auth/register
func registerHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

	db.mu.Lock()
	defer db.mu.Unlock()

	// Basic check for existing user
	for _, u := range db.users {
		if u.Username == req.Username {
			writeError(w, http.StatusConflict, "username already exists")
			return
		}
	}

	db.userCounter++
	id := fmt.Sprintf("U%d", db.userCounter)
	db.users[id] = User{ID: id, Username: req.Username, PasswordHash: string(hash)}

	writeJSON(w, http.StatusCreated, map[string]string{"message": "user registered successfully"})
}

// POST /auth/login
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	db.mu.RLock()
	var user User
	var found bool
	for _, u := range db.users {
		if u.Username == req.Username {
			user = u
			found = true
			break
		}
	}
	db.mu.RUnlock()

	if !found || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &jwt.RegisteredClaims{
		Subject:   user.ID,
		ExpiresAt: jwt.NewNumericDate(expirationTime),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(jwtKey)

	writeJSON(w, http.StatusOK, map[string]string{"token": tokenString})
}

// POST /tickets
func createTicketHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Title       string `json:"title"`
		Description string `json:"description"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	req.Title = strings.TrimSpace(req.Title)
	req.Description = strings.TrimSpace(req.Description)
	if req.Title == "" || req.Description == "" {
		writeError(w, http.StatusBadRequest, "title and description are required")
		return
	}
	userID := r.Header.Get("X-User-ID")

	db.mu.Lock()
	db.ticketCounter++
	ticket := Ticket{
		ID:          fmt.Sprintf("T%d", db.ticketCounter),
		UserID:      userID,
		Title:       req.Title,
		Description: req.Description,
		Status:      "open", // Default status
	}
	db.tickets[ticket.ID] = ticket
	db.mu.Unlock()

	writeJSON(w, http.StatusCreated, ticket)
}

// GET /tickets
func listTicketsHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")

	db.mu.RLock()
	var myTickets []Ticket
	for _, t := range db.tickets {
		if t.UserID == userID {
			myTickets = append(myTickets, t)
		}
	}
	db.mu.RUnlock()

	if myTickets == nil {
		myTickets = []Ticket{} // Return empty array instead of null
	}
	writeJSON(w, http.StatusOK, myTickets)
}

// GET /tickets/{id}
func getTicketHandler(w http.ResponseWriter, r *http.Request) {
	id := ticketIDFromPath(r)
	userID := r.Header.Get("X-User-ID")

	db.mu.RLock()
	ticket, exists := db.tickets[id]
	db.mu.RUnlock()

	if !exists {
		writeError(w, http.StatusNotFound, "ticket not found")
		return
	}
	if ticket.UserID != userID {
		writeError(w, http.StatusForbidden, "you can only access your own tickets")
		return
	}

	writeJSON(w, http.StatusOK, ticket)
}

// PATCH /tickets/{id}/status
func updateTicketStatusHandler(w http.ResponseWriter, r *http.Request) {
	id := ticketIDFromPath(r)
	userID := r.Header.Get("X-User-ID")

	var req struct {
		Status string `json:"status"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	db.mu.Lock()
	defer db.mu.Unlock()

	ticket, exists := db.tickets[id]
	if !exists {
		writeError(w, http.StatusNotFound, "ticket not found")
		return
	}
	if ticket.UserID != userID {
		writeError(w, http.StatusForbidden, "you can only update your own tickets")
		return
	}

	if ticket.Status == "closed" {
		writeError(w, http.StatusBadRequest, "closed tickets cannot be reopened")
		return
	}

	isValidTransition := false
	if ticket.Status == "open" && (req.Status == "in_progress" || req.Status == "closed") {
		isValidTransition = true
	} else if ticket.Status == "in_progress" && req.Status == "closed" {
		isValidTransition = true
	} else if ticket.Status == req.Status {
		isValidTransition = true
	}

	if !isValidTransition {
		writeError(w, http.StatusBadRequest, "invalid status transition")
		return
	}

	ticket.Status = req.Status
	db.tickets[id] = ticket
	writeJSON(w, http.StatusOK, ticket)
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/health" {
			if requireMethod(w, r, http.MethodGet) {
				healthHandler(w, r)
			}
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/auth/register", func(w http.ResponseWriter, r *http.Request) {
		if requireMethod(w, r, http.MethodPost) {
			registerHandler(w, r)
		}
	})
	mux.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if requireMethod(w, r, http.MethodPost) {
			loginHandler(w, r)
		}
	})

	mux.HandleFunc("/tickets", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			createTicketHandler(w, r)
		case http.MethodGet:
			listTicketsHandler(w, r)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}))
	mux.HandleFunc("/tickets/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") {
			if requireMethod(w, r, http.MethodPatch) {
				updateTicketStatusHandler(w, r)
			}
			return
		}
		if requireMethod(w, r, http.MethodGet) {
			getTicketHandler(w, r)
		}
	}))

	fmt.Println("Ticket system API is running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
