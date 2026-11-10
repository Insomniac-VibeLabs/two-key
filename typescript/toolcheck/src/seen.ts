// Copyright 2026 Insomniac-VibeLabs
// Author: Stephan Busch
// SPDX-License-Identifier: Apache-2.0
/**
 * The seen record: the jtis this tool has accepted, in a SQLite file only its owner can read. It is the same table
 * the Python helper keeps (`seen (jti TEXT PRIMARY KEY, until REAL NOT NULL)`), so a Python and a TypeScript copy of
 * one server can share one file and refuse each other's replays. Adding a jti is one atomic step; a jti already
 * there is refused. Entries go once their token can no longer be valid.
 *
 * It uses Node's built-in `node:sqlite` (Node 22.13 and later). Where that is missing, opening the record fails, so
 * the helper cannot be made and no call is served without replay protection.
 */

import { closeSync } from "node:fs";
import type { DatabaseSync } from "node:sqlite";
import { accessProblem, createIfMissing, openNoFollow } from "./files.ts";

type SqliteModule = typeof import("node:sqlite");

let sqlite: SqliteModule | undefined;

async function loadSqlite(): Promise<SqliteModule> {
  sqlite ??= await import("node:sqlite");
  return sqlite;
}

export class SeenRecord {
  readonly path: string;
  readonly #module: SqliteModule;

  private constructor(path: string, module: SqliteModule) {
    this.path = path;
    this.#module = module;
  }

  /** Open (creating it owner-only when missing) the record at `path`. */
  static async open(path: string): Promise<SeenRecord> {
    const module = await loadSqlite();
    createIfMissing(path);
    const fd = openNoFollow(path);
    let problem: string | null;
    try {
      problem = accessProblem(fd);
    } finally {
      closeSync(fd);
    }
    if (problem !== null) {
      throw new Error(`seen record ${path}: ${problem}`);
    }
    const record = new SeenRecord(path, module);
    record.#use((db) => { db.exec("CREATE TABLE IF NOT EXISTS seen (jti TEXT PRIMARY KEY, until REAL NOT NULL)"); });
    return record;
  }

  #use<T>(work: (db: DatabaseSync) => T): T {
    const db = new this.#module.DatabaseSync(this.path);
    try {
      db.exec("PRAGMA busy_timeout = 10000");
      return work(db);
    } finally {
      db.close();
    }
  }

  /** Record `jti` until `until`; false when it was already there. Prunes what has expired. */
  add(jti: string, until: number, now: number): boolean {
    return this.#use((db) => {
      db.exec("BEGIN IMMEDIATE");
      try {
        db.prepare("DELETE FROM seen WHERE until < ?").run(now);
        const known = db.prepare("SELECT 1 FROM seen WHERE jti = ?").get(jti);
        if (known === undefined) {
          db.prepare("INSERT INTO seen (jti, until) VALUES (?, ?)").run(jti, until);
        }
        db.exec("COMMIT");
        return known === undefined;
      } catch (e) {
        db.exec("ROLLBACK");
        throw e;
      }
    });
  }
}
