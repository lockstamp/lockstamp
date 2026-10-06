import { createClient } from "@supabase/supabase-js";

// DEMO MISTAKE: the service_role key bypasses every security rule and must never be in browser code.
// DEMO ONLY: this key is fake.
export const supabaseAdmin = createClient(
  "https://demoprojectref0000000.supabase.co",
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRlbW9wcm9qZWN0cmVmMDAwMDAwMCIsImlhdCI6MTc2NzIyNTYwMCwiZXhwIjoyMDgyNzU4NDAwLCJyb2xlIjoic2VydmljZV9yb2xlIn0.DEMOonlyNOTaREALsignatureDEMOonlyNOTaREALsig",
);
