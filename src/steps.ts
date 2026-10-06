// Progress steps, shared by the checker and the web page (kept separate so the page doesn't load the database engine).
export const STEPS = {
  load: "Loading the test database (a one-time download of about 6 MB)",
  rebuild: "Rebuilding your database structure in a private test copy",
  check: "Checking access rules and database functions",
  attack: "Trying attacks against the current setup",
  fix: "Applying the fix and trying the attacks again",
} as const;

export const STEP_ORDER: string[] = [STEPS.load, STEPS.rebuild, STEPS.check, STEPS.attack, STEPS.fix];
