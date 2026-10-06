import { createClient } from "@supabase/supabase-js";

// The anon (public) key is meant to ship in the browser; Row Level Security protects the data.
// DEMO ONLY: this key is fake.
export const supabase = createClient(
  "https://demoprojectref0000000.supabase.co",
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRlbW9wcm9qZWN0cmVmMDAwMDAwMCIsImlhdCI6MTc2NzIyNTYwMCwiZXhwIjoyMDgyNzU4NDAwLCJyb2xlIjoiYW5vbiJ9.DEMOonlyNOTaREALsignatureDEMOonlyNOTaREALsig",
);
