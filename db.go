package main

import (
    "database/sql"
    _ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func initDB(path string) error {
    var err error
    db, err = sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on")
    if err != nil { return err }
    _, err = db.Exec(`
    CREATE TABLE IF NOT EXISTS agents (
        id TEXT PRIMARY KEY,
        hostname TEXT, os TEXT, arch TEXT, ip TEXT,
        last_seen INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        cmd TEXT NOT NULL,
        args TEXT,
        nonce TEXT NOT NULL UNIQUE,
        ts INTEGER NOT NULL,
        signature TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created INTEGER NOT NULL,
        FOREIGN KEY(agent_id) REFERENCES agents(id)
    );
    CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        output TEXT, error TEXT,
        created INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_tasks_agent_status ON tasks(agent_id, status);`)
    return err
}
