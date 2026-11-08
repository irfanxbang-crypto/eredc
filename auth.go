package main

import (
    "crypto/rand"
    "net/http"
    "strings"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "golang.org/x/crypto/bcrypt"
    "golang.org/x/time/rate"
)

var (
    jwtSecret    []byte
    operatorHash []byte
    loginLimiter = rate.NewLimiter(5, 5)
)

func initAuth(user, pass string) {
    jwtSecret = make([]byte, 32)
    rand.Read(jwtSecret)
    h, _ := bcrypt.GenerateFromPassword([]byte(pass), 12)
    operatorHash = h
    operatorUser = user
}

var operatorUser string

func issueToken() (string, error) {
    t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "sub": operatorUser,
        "exp": time.Now().Add(2 * time.Hour).Unix(),
        "iat": time.Now().Unix(),
    })
    return t.SignedString(jwtSecret)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        h := r.Header.Get("Authorization")
        if !strings.HasPrefix(h, "Bearer ") {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        tok := strings.TrimPrefix(h, "Bearer ")
        _, err := jwt.Parse(tok, func(t *jwt.Token) (interface{}, error) {
            if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, jwt.ErrSignatureInvalid
            }
            return jwtSecret, nil
        })
        if err != nil {
            http.Error(w, "invalid token", http.StatusUnauthorized)
            return
        }
        next(w, r)
    }
}
