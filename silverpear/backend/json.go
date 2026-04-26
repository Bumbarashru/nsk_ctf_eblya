package main

import (
    "crypto/sha256"
    "crypto/sha1"
    "crypto/subtle"
    "encoding/hex"
    "encoding/json"
    "errors"
    "net/http"
    "strconv"
    "strings"

    "github.com/lib/pq"
    "golang.org/x/crypto/bcrypt"
)

var errUnauthorized = errors.New("unauthorized")

func writeJSON(w http.ResponseWriter, status int, payload any) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    _ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
    writeJSON(w, status, map[string]string{"error": message})
}

func readJSON(r *http.Request, dst any) error {
    defer r.Body.Close()
    decoder := json.NewDecoder(r.Body)
    decoder.DisallowUnknownFields()
    return decoder.Decode(dst)
}

func parsePathInt(r *http.Request, key string) (int64, error) {
    return strconv.ParseInt(r.PathValue(key), 10, 64)
}

// hashPassword возвращает bcrypt-хеш пароля.
func hashPassword(password string) string {
    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        // при ошибке возвращаем пустую строку – паника недопустима, но ошибка будет поймана при проверке
        return ""
    }
    return string(hash)
}

// checkPassword проверяет пароль против bcrypt-хеша.
// Если хеш старый (SHA256), выполняет миграцию на bcrypt.
// Возвращает (ok, newHash), где newHash непуст, если хеш нужно обновить в БД.
func checkPassword(storedHash, password string) (ok bool, needUpgrade bool, newHash string) {
    // Попытка сравнить как bcrypt
    err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
    if err == nil {
        return true, false, ""
    }
    // Попытка сравнить как старый SHA256
    legacyHash := legacyHashPassword(password)
    if subtle.ConstantTimeCompare([]byte(storedHash), []byte(legacyHash)) == 1 {
        // успешный вход со старым хешем – нужно обновить на bcrypt
        newBcrypt, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
        return true, true, string(newBcrypt)
    }
    return false, false, ""
}

// legacyHashPassword – старый SHA256 (только для миграции)
func legacyHashPassword(password string) []byte {
    sum := sha256.Sum256([]byte(password))
    return sum[:]
}

func usernameHash(value string) string {
    sum := sha1.Sum([]byte(strings.ToLower(value)))
    return hex.EncodeToString(sum[:4])
}

func postgresErrorCode(err error) string {
    var pqErr *pq.Error
    if errors.As(err, &pqErr) {
        return string(pqErr.Code)
    }
    return ""
}

func isUniqueViolation(err error) bool {
    return postgresErrorCode(err) == "23505"
}

func isForeignKeyViolation(err error) bool {
    return postgresErrorCode(err) == "23503"
}

func isInvalidTextRepresentation(err error) bool {
    return postgresErrorCode(err) == "22P02"
}