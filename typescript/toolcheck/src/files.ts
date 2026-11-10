// Copyright 2026 Insomniac-VibeLabs
// Author: Stephan Busch
// SPDX-License-Identifier: Apache-2.0
/**
 * Reading and creating the helper's files the way Two-Key does: no symbolic link as the last part of the path, a
 * regular file, and (on Linux and macOS) readable and writable by its owner only. On Windows the helper does not read
 * access lists; keep the files in a folder only the tool's account can open (README, "Windows").
 */

import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from "node:fs";

export const WINDOWS = process.platform === "win32";
// Not defined on Windows, where openNoFollow checks for a link first.
const NO_FOLLOW: number = (constants as Partial<typeof constants>).O_NOFOLLOW ?? 0;

export class FileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FileError";
  }
}

/** Open `path` for reading without following a symbolic link. */
export function openNoFollow(path: string, flags: number = constants.O_RDONLY): number {
  if (WINDOWS && lstatSync(path).isSymbolicLink()) {
    throw new FileError(`${path} is a symbolic link`);
  }
  return openSync(path, flags | NO_FOLLOW);
}

/** Why the open file `fd` is not owner-only, or null. Checked on the descriptor, so it cannot be swapped. */
export function accessProblem(fd: number): string | null {
  const st = fstatSync(fd);
  if (!st.isFile()) {
    return "not a regular file";
  }
  if (!WINDOWS && (st.mode & 0o077) !== 0) {
    return `mode ${(st.mode & 0o777).toString(8).padStart(4, "0")}, readable by group or others`;
  }
  return null;
}

/** The text of a file only its owner can read, at most `limit` bytes. `code` starts each refusal. */
export function readOwnerOnly(path: string, code: string, limit: number): string {
  let fd: number;
  try {
    fd = openNoFollow(path);
  } catch (e) {
    throw new FileError(`${code}_unreadable: ${path}: ${(e as NodeJS.ErrnoException).code ?? "cannot open"}`);
  }
  try {
    const problem = accessProblem(fd);
    if (problem !== null) {
      throw new FileError(`${code}_insecure: ${path} is ${problem}; run chmod 600 ${path}`);
    }
    const buffer = Buffer.alloc(limit + 1);
    let size = 0;
    let n: number;
    do {
      n = readSync(fd, buffer, size, buffer.length - size, null);
      size += n;
    } while (n > 0 && size <= limit);
    if (size > limit) {
      throw new FileError(`${code}_invalid: ${path} is over ${String(limit)} bytes`);
    }
    return buffer.subarray(0, size).toString("utf8");
  } finally {
    closeSync(fd);
  }
}

/** Create `path` owner-only (mode 0600) when it is not there; an existing file is left as it is. */
export function createIfMissing(path: string): void {
  try {
    closeSync(openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NO_FOLLOW, 0o600));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") {
      throw e;
    }
  }
}
