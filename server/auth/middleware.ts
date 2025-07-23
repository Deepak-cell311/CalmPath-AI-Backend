import type { Request, Response, NextFunction, Express } from "express";
export function setupAuth(app: Express) {
  // placeholder
}

export function isAuthenticated(req: Request, res: Response, next: NextFunction) {
  if (req.session && req.session.user) {
    console.log("Session:", req.session)
    req.user = req.session.user;
    return next();
  }
  res.status(401).json({ message: "Unauthorized" });
} 