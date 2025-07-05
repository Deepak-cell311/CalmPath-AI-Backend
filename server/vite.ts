import type { Express } from "express";
import type { Server } from "http";

export function log(message: string) {
  // A simple logger
  console.log(message);
}

export async function setupVite(_app: Express, _server: Server) {
  // This is a placeholder since there is no frontend to serve.
  log("Skipping Vite setup for backend-only server.");
}

export function serveStatic(_app: Express) {
  // This is a placeholder since there is no frontend to serve.
  log("Skipping static file serving for backend-only server.");
} 