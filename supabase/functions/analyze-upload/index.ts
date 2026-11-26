import { createAnonClient, createServiceClient } from "../_shared/supabase.ts";
import { errorResponse } from "../_shared/cors.ts";
import { handleAnalyzeUploadRequest } from "./handler.ts";

Deno.serve(async (req: Request) => {
  try {
    const authHeader = req.headers.get("authorization") ?? undefined;
    const adminClient = createServiceClient();
    const anonClient = createAnonClient(authHeader);
    return await handleAnalyzeUploadRequest(req, adminClient, anonClient);
  } catch {
    return errorResponse("Internal upload analysis error", 500);
  }
});
