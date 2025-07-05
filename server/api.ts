import express  from "express";
import { registerRoutes } from "./routes";
import { registerVoiceRoutes } from "./voice";

  const app = express();
  // Register all routes
  registerRoutes(app);
  registerVoiceRoutes(app);
