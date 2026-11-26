import { createServiceClient } from "../_shared/supabase.ts";
import { errorResponse } from "../_shared/cors.ts";
import { handleHeartbeatRequest } from "./handler.ts";

Deno.serve(async (req: Request) => {
  try {
    const adminClient = createServiceClient();
    return await handleHeartbeatRequest(req, adminClient);
  } catch {
    return errorResponse("Internal heartbeat error", 500);
  }
});
