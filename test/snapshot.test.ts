import { describe, expect, it } from "vitest";
import { parseSnapshot, SnapshotError, SNAPSHOT_QUERY } from "../src/snapshot.js";

function failure(text: string): SnapshotError {
  try {
    parseSnapshot(text);
  } catch (err) {
    if (err instanceof SnapshotError) return err;
    throw err;
  }
  throw new Error("expected the paste to be rejected");
}

describe("parseSnapshot explains bad pastes in plain words", () => {
  it("spots the query itself pasted back", () => {
    expect(failure(SNAPSHOT_QUERY).message).toMatch(/query itself/);
  });

  it("spots a result that was cut off", () => {
    expect(failure('{"version": 2, "tables": [').kind).toBe("truncated");
  });

  it("rejects a damaged quoted cell without a raw parser error", () => {
    expect(failure(JSON.stringify('{"version": 2, "tab')).kind).toBe("truncated");
  });

  it("rejects JSON that isn't a snapshot", () => {
    expect(failure('{"hello": "world"}').kind).toBe("not-snapshot");
  });

  it("rejects a snapshot with lists missing, in plain words", () => {
    expect(failure('{"version": 2, "tables": []}').message).toMatch(/only part of the snapshot/);
  });

  it("accepts the cell copied with its surrounding quotes", () => {
    expect(parseSnapshot(JSON.stringify(JSON.stringify(SNAP))).version).toBe(2);
  });

  it("accepts the SQL editor's CSV copy", () => {
    const csv = `snapshot\n"${JSON.stringify(SNAP).replace(/"/g, '""')}"`;
    expect(parseSnapshot(csv).version).toBe(2);
  });

  it("accepts the SQL editor's markdown copy, with escaped pipes", () => {
    const json = JSON.stringify({ ...SNAP, functions: [{ name: "f", args: "", definition: "select 'a' || 'b'", anon_execute: false, authenticated_execute: false }] });
    const markdown = `| snapshot |\n| --- |\n| ${json.replace(/\|/g, "\\|")} |`;
    expect(parseSnapshot(markdown).functions[0].definition).toBe("select 'a' || 'b'");
  });
});

const SNAP = { version: 2, tables: [], enums: [], policies: [], functions: [], views: [], triggers: [], buckets: [] };
