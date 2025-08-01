import type { Request, Response, NextFunction, Express } from "express";

export function setupAuth(app: Express) {
  // placeholder
}

export function isAuthenticated(req: Request, res: Response, next: NextFunction) {
  console.log("Authentication check - Origin:", req.get('Origin'));
  console.log("Authentication check - Cookie header:", req.get('Cookie'));
  console.log("Authentication check - Session ID:", req.sessionID);
  console.log("Authentication check - Session data:", req.session);
  
  if (req.session && req.session.user) {
    console.log("User authenticated:", req.session.user.email);
    req.user = req.session.user;
    return next();
  }
  
  console.log("Authentication failed - no valid session");
  res.status(401).json({ message: "Unauthorized" });
} 