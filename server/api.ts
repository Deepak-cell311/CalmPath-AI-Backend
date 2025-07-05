import { Router } from "express";
import { registerRoutes } from "./routes";
import { registerVoiceRoutes } from "./voice";

export function createApiRouter(): Router {
  const router = Router();
  
  // Register all routes
  registerRoutes(router);
  registerVoiceRoutes(router);

  return router;
} 