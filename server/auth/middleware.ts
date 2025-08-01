import type { Request, Response, NextFunction, Express } from "express";
export function setupAuth(app: Express) {
  // placeholder
}

export function isAuthenticated(req: Request, res: Response, next: NextFunction) {
  if (req.session && req.session.user) {
    console.log("Session found:", req.session.user);
    req.user = req.session.user;
    return next();
  }
  
  console.log("No session found, user not authenticated");
  res.status(401).json({ message: "Unauthorized - Please log in" });
} 