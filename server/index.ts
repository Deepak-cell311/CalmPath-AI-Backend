import * as dotenv from "dotenv";
dotenv.config();

import express, { type Request, Response, NextFunction } from "express";
import cors, { CorsOptions } from "cors";
import { registerRoutes } from "../server/routes";
import { setupVite, serveStatic, log } from "./vite";
import { registerVoiceRoutes } from "./voice";
import webhookHandler from "./webhook";
import stripeRoutes from "./stripe";
import path from "path";
import fs from "fs";

const app = express();

// Trust proxy for correct protocol detection in production
// This tells Express to trust the X-Forwarded-* headers from the proxy
app.set('trust proxy', 1);
app.enable('trust proxy');

// --- CORS: Allow credentials and set correct origin for production ---
const allowedOrigins = [
  "https://app.calmpath.ai",
  "https://calm-path-ai.vercel.app",
  "http://localhost:3000",
  "https://calmpathfrontend-sid-production.up.railway.app",
];

function isAllowedOrigin(origin: string): boolean {
  if (allowedOrigins.includes(origin)) return true;
  // Allow Railway/Vercel preview subdomains if needed
  if (origin.endsWith(".up.railway.app")) return true;
  if (origin.endsWith(".vercel.app")) return true;
  return false;
}

const corsOptions: CorsOptions = {
  origin: function (origin: string | undefined, callback: any) {
    if (!origin) return callback(null, true); // allow no-origin (e.g., mobile apps or curl)
    if (isAllowedOrigin(origin)) return callback(null, true);
    console.error("CORS blocked origin:", origin);
    return callback(new Error("Not allowed by CORS"));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
};

// Apply to all requests
app.use(cors(corsOptions));

// Respond to preflight (OPTIONS) requests
app.options("*", cors(corsOptions));

// Raw body for Stripe webhooks - must come BEFORE express.json()
app.use('/webhook', express.raw({ type: 'application/json' }));
app.use('/api/billing/webhook', express.raw({ type: 'application/json' }));

// JSON parsing middleware - only for non-webhook routes
app.use((req, res, next) => {
  if (req.path.startsWith('/webhook') || req.path.startsWith('/api/billing/webhook')) {
    return next();
  }
  express.json()(req, res, next);
});

app.use((req, res, next) => {
  if (req.path.startsWith('/webhook') || req.path.startsWith('/api/billing/webhook')) {
    return next();
  }
  express.urlencoded({ extended: false })(req, res, next);
});

app.use('/api/stripe', stripeRoutes);
app.post('/webhook', webhookHandler as any);

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  // Ensure uploads directory exists
  const uploadsPath = path.join(__dirname, 'uploads');
  if (!fs.existsSync(uploadsPath)) {
    fs.mkdirSync(uploadsPath, { recursive: true });
    log(`Created uploads directory: ${uploadsPath}`);
  }

  const server = await registerRoutes(app);
  registerVoiceRoutes(app);

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    res.status(status).json({ message });
    throw err;
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // ALWAYS serve the app on port 5000
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const port = 5000;
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true,
  }, () => {
    log(`serving on port ${port}`);
  });
})(); 
