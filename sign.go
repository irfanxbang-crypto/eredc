package main

import (
    "crypto/ed25519"
    "crypto/rand"
    "crypto/x509"
    "encoding/base64"
    "encoding/pem"
    "fmt"
    "os"

    "c2go/shared"
)

var (
    operatorPriv ed25519.PrivateKey
    operatorPub  ed25519.PublicKey
)

func loadOrCreateOperatorKey(privPath, pubPath string) error {
    if b, err := os.ReadFile(privPath); err == nil {
        blk, _ := pem.Decode(b)
        k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
        if err != nil { return err }
        operatorPriv = k.(ed25519.PrivateKey)

        pb, _ := os.ReadFile(pubPath)
        blk2, _ := pem.Decode(pb)
        operatorPub = blk2.Bytes
        return nil
    }
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { return err }
    operatorPriv, operatorPub = priv, pub

    privDer, _ := x509.MarshalPKCS8PrivateKey(priv)
    os.WriteFile(privPath,
        pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY", Bytes:privDer}), 0600)
    os.WriteFile(pubPath,
        pem.EncodeToMemory(&pem.Block{Type:"PUBLIC KEY", Bytes:pub}), 0644)
    return nil
}

func taskSigningMsg(t shared.Task) []byte {
    return []byte(fmt.Sprintf("%s|%s|%s|%s|%s|%d",
        t.ID, t.AgentID, t.Cmd, t.Args, t.Nonce, t.Ts))
}

func signTask(t shared.Task) string {
    sig := ed25519.Sign(operatorPriv, taskSigningMsg(t))
    return base64.StdEncoding.EncodeToString(sig)
}

func operatorPubB64() string {
    return base64.StdEncoding.EncodeToString(operatorPub)
}
