import { describe, expect, it } from "vitest";
import { autoFixable, openAudience } from "../src/checks.js";
import type { Policy, Table } from "../src/types.js";

const policy = (cmd: Policy["cmd"], roles: string[], using: string | null, withCheck: string | null = null): Policy => ({
  name: "p",
  permissive: true,
  roles,
  cmd,
  using,
  withCheck,
});

const table = (name: string, exposure: Table["exposure"], ownerColumns = ["user_id"]): Table => ({
  schema: "public",
  name,
  rlsEnabled: true,
  columns: [],
  policies: [],
  foreignKeys: [],
  access: { anon: ["SELECT"], authenticated: ["SELECT", "INSERT", "UPDATE", "DELETE"] },
  ownerColumns,
  sensitive: false,
  privilege: false,
  protectedColumns: [],
  exposure,
});

describe("openAudience", () => {
  it("treats `true` for public roles as open to anyone", () => {
    expect(openAudience(policy("SELECT", ["public"], "true"))).toBe("anyone");
  });

  it("treats 'is someone logged in' checks as open to any logged-in user", () => {
    expect(openAudience(policy("SELECT", ["authenticated"], "(auth.uid() IS NOT NULL)"))).toBe("logged-in");
    expect(openAudience(policy("SELECT", ["public"], "(( SELECT auth.uid() AS uid) IS NOT NULL)"))).toBe("logged-in");
    expect(openAudience(policy("UPDATE", ["public"], "(auth.role() = 'authenticated'::text)"))).toBe("logged-in");
  });

  it("does not flag rules that compare against the row owner or a role check", () => {
    expect(openAudience(policy("SELECT", ["authenticated"], "(auth.uid() = user_id)"))).toBeNull();
    expect(openAudience(policy("ALL", ["authenticated"], "has_role(auth.uid(), 'admin'::app_role)"))).toBeNull();
  });

  it("reads INSERT rules from WITH CHECK", () => {
    expect(openAudience(policy("INSERT", ["authenticated"], null, "true"))).toBe("logged-in");
  });
});

describe("autoFixable", () => {
  const openRead = policy("SELECT", ["public"], "true");
  const openWrite = policy("UPDATE", ["authenticated"], "true");

  it("locks down open reads only when the data is clearly private", () => {
    expect(autoFixable(table("notes", "private"), openRead)).toBe(true);
    expect(autoFixable(table("reviews", "public"), openRead)).toBe(false);
    expect(autoFixable(table("widgets", "unknown"), openRead)).toBe(false);
  });

  it("always fixes rules that let users change other users' rows", () => {
    expect(autoFixable(table("reviews", "public"), openWrite)).toBe(true);
  });

  it("leaves tables with several user columns to a human", () => {
    expect(autoFixable(table("messages", "private", ["sender_id", "recipient_id"]), openWrite)).toBe(false);
  });
});
