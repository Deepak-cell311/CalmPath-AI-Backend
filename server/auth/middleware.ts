import type { Request, Response, NextFunction, Express } from "express";
export function setupAuth(app: Express) {
  // placeholder
}
export function isAuthenticated(req: Request, res: Response, next: NextFunction) {
  // placeholder for now, should check session
  // In a real app, you'd have something like:
  // if (req.user) {
  //   next();
  // } else {
  //   res.status(401).send('Unauthorized');
  // }
  next();
} 