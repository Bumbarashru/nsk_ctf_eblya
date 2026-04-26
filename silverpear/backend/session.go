package main

import (
    "crypto/rand"
    "encoding/hex"
    "sync"
    "time"
)

type sessionStore struct {
    mu       sync.RWMutex
    sessions map[string]sessionEntry
}

type sessionEntry struct {
    userID    int64
    createdAt time.Time
}

const sessionTTL = 7 * 24 * time.Hour

func newSessionStore() *sessionStore {
    s := &sessionStore{
        sessions: make(map[string]sessionEntry),
    }
    // фоновая очистка просроченных сессий каждые 10 минут
    go s.cleanupLoop()
    return s
}

func (s *sessionStore) Create(userID int64) (string, error) {
    buf := make([]byte, 32)
    if _, err := rand.Read(buf); err != nil {
        return "", err
    }
    token := hex.EncodeToString(buf)
    s.mu.Lock()
    defer s.mu.Unlock()
    s.sessions[token] = sessionEntry{
        userID:    userID,
        createdAt: time.Now(),
    }
    return token, nil
}

func (s *sessionStore) Get(token string) (int64, bool) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    entry, ok := s.sessions[token]
    if !ok {
        return 0, false
    }
    if time.Since(entry.createdAt) > sessionTTL {
        // просрочена – не возвращаем, но не удаляем здесь (удалится при очистке)
        return 0, false
    }
    return entry.userID, true
}

func (s *sessionStore) Delete(token string) {
    s.mu.Lock()
    defer s.mu.Unlock()
    delete(s.sessions, token)
}

func (s *sessionStore) cleanupLoop() {
    ticker := time.NewTicker(10 * time.Minute)
    for range ticker.C {
        s.cleanup()
    }
}

func (s *sessionStore) cleanup() {
    s.mu.Lock()
    defer s.mu.Unlock()
    now := time.Now()
    for token, entry := range s.sessions {
        if now.Sub(entry.createdAt) > sessionTTL {
            delete(s.sessions, token)
        }
    }
}