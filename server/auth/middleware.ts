import type { Request, Response, NextFunction, Express } from "express";
export function setupAuth(app: Express) {
  // placeholder
}

export function isAuthenticated(req: Request, res: Response, next: NextFunction) {
  // Allow unauthenticated access - comment out authentication check
  // if (req.session && req.session.user) {
  //   console.log("Session:", req.session)
  //   req.user = req.session.user;
  //   return next();
  // }
  // res.status(401).json({ message: "Unauthorized" });
  
  // Set a default user if no session exists
  if (req.session && req.session.user) {
    console.log("Session:", req.session)
    req.user = req.session.user;
  } else {
    // Create a default user for unauthenticated access
    req.user = {
      id: 1,
      email: "demo@example.com",
      firstName: "Demo",
      accountType: "Facility Staff"
    };
  }
  return next();
} 