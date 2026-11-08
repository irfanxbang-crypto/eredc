package shared

type Task struct {
    ID        string `json:"id"`
    AgentID   string `json:"agent_id"`
    Cmd       string `json:"cmd"`
    Args      string `json:"args"`
    Nonce     string `json:"nonce"`
    Ts        int64  `json:"ts"`
    Signature string `json:"signature"`
}

type Result struct {
    TaskID  string `json:"task_id"`
    AgentID string `json:"agent_id"`
    Output  string `json:"output"`
    Error   string `json:"error,omitempty"`
}

type Beacon struct {
    AgentID  string `json:"agent_id"`
    Hostname string `json:"hostname"`
    OS       string `json:"os"`
    Arch     string `json:"arch"`
    IP       string `json:"ip"`
}

type LoginResp struct {
    Token       string `json:"token"`
    OperatorPub string `json:"operator_pub"` // base64 Ed25519 public key
}

const (
    TaskPending = "pending"
    TaskRunning = "running"
    TaskDone    = "done"
)

var AllowedCmds = map[string]bool{
    "exec": true, "sleep": true, "update": true, "kill": true, "info": true,
}
