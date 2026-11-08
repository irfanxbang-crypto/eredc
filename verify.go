package main

import (
    "crypto/ed25519"
    "encoding/base64"
    "fmt"
    "sync"
    "time"

    "c2go/shared"
)

var (
    operatorPub ed25519.PublicKey
    seenNonces  = map[string]int64{}
    nonceMtx    sync.Mutex
)

func setOperatorPub(b64 string) error {
    b, err := base64.StdEncoding.DecodeString(b64)
    if err != nil { return err }
    if len(b) != ed25519.PublicKeySize {
        return fmt.Errorf("bad pubkey size")
    }
    operatorPub = ed25519.PublicKey(b)
    return nil
}

func verifyTask(t shared.Task) bool {
    if operatorPub == nil { return false }

    // anti-replay window
    if time.Now().Unix()-t.Ts > 120 { return false }

    nonceMtx.Lock()
    if _, ok := seenNonces[t.Nonce]; ok {
        nonceMtx.Unlock(); return false
    }
    seenNonces[t.Nonce] = t.Ts
    nonceMtx.Unlock()

    msg := []byte(fmt.Sprintf("%s|%s|%s|%s|%s|%d",
        t.ID, t.AgentID, t.Cmd, t.Args, t.Nonce, t.Ts))
    sig, err := base64.StdEncoding.DecodeString(t.Signature)
    if err != nil { return false }
    return ed25519.Verify(operatorPub, msg, sig)
}
