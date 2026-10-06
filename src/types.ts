export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface Finding {
  rule: string;
  severity: Severity;
  target: string;
  title: string;
  plain: string;
  fix: string;
  autoFixed: boolean;
}

export interface Column {
  name: string;
  dataType: string;
  udtName: string;
  nullable: boolean;
  hasDefault: boolean;
  // Literal values a single-column CHECK constraint allows, e.g. status in ('draft', 'published').
  allowedValues: string[];
}

export type PolicyCommand = "SELECT" | "INSERT" | "UPDATE" | "DELETE" | "ALL";

export interface Policy {
  name: string;
  permissive: boolean;
  roles: string[];
  cmd: PolicyCommand;
  using: string | null;
  withCheck: string | null;
}

export interface ForeignKey {
  column: string;
  refSchema: string;
  refTable: string;
  refColumn: string;
}

export interface ApiAccess {
  anon: string[];
  authenticated: string[];
}

export interface Table {
  schema: string;
  name: string;
  rlsEnabled: boolean;
  columns: Column[];
  policies: Policy[];
  foreignKeys: ForeignKey[];
  access: ApiAccess;
  ownerColumns: string[];
  // Billing or permission data: users may read their own rows but must never write them.
  sensitive: boolean;
  // Grants rights (roles, memberships): the test attacker must never be seeded into it.
  privilege: boolean;
  // Columns a user must not set on their own row (role, plan, credits, ...).
  protectedColumns: string[];
  // Whether rows look private, intentionally public, or can't be told apart.
  exposure: Exposure;
}

export type Exposure = "private" | "public" | "unknown";

export interface View {
  schema: string;
  name: string;
  materialized: boolean;
  securityInvoker: boolean;
  apiReadable: boolean;
}

export interface DefinerFunction {
  schema: string;
  name: string;
  args: string;
  anonCanExecute: boolean;
  authenticatedCanExecute: boolean;
  searchPathSet: boolean;
  argCount: number;
  returnsVoid: boolean;
  readsAuthUsers: boolean;
}

export interface Bucket {
  id: string;
  public: boolean;
}

export interface DbSchema {
  tables: Table[];
  views: View[];
  functions: DefinerFunction[];
  buckets: Bucket[];
}

export interface LoadIssue {
  file: string;
  statement: string;
  error: string;
}

export interface ProbeRow {
  table: string;
  test: string;
  exposed: boolean | null;
  detail: string;
}

export interface ProofRow {
  table: string;
  test: string;
  before: boolean | null;
  after: boolean | null;
  // Whether fix.sql changes anything for this table; if not, a remaining exposure is a decision for the owner.
  autoFixed: boolean;
}
