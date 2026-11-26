import { createServiceClient } from "../_shared/supabase.ts";
import { errorResponse } from "../_shared/cors.ts";
import { handleIngestRequest } from "./handler.ts";

Deno.serve(async (req: Request) => {
  try {
    const adminClient = createServiceClient();
    return await handleIngestRequest(req, adminClient);
  } catch {
    return errorResponse("Internal ingestion error", 500);
  }
});
