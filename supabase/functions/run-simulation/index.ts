import { createAnonClient, createServiceClient } from "../_shared/supabase.ts";
import { errorResponse } from "../_shared/cors.ts";
import { handleRunSimulationRequest } from "./handler.ts";

Deno.serve(async (req: Request) => {
  try {
    const authHeader = req.headers.get("authorization") ?? undefined;
    const adminClient = createServiceClient();
    const anonClient = createAnonClient(authHeader);
    return await handleRunSimulationRequest(req, adminClient, anonClient);
  } catch {
    return errorResponse("Internal simulation error", 500);
  }
});
