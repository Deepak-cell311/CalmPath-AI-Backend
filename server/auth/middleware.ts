import type { Request, Response, NextFunction, Express } from "express";
import { storage } from "../storage";

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

export function isAuthenticatedToken(req: Request, res: Response, next: NextFunction) {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: "No token provided" });
    }
    
    const token = authHeader.substring(7); // Remove 'Bearer '
    
    try {
      const decoded = JSON.parse(Buffer.from(token, 'base64').toString());
      const userId = decoded.userId;
      
      if (!userId) {
        return res.status(401).json({ message: "Invalid token" });
      }
      
      // Set user in request for other middleware/routes to use
      req.user = { userId: userId };
      return next();
      
    } catch (tokenError) {
      console.error('Token decode error:', tokenError);
      res.status(401).json({ message: "Invalid token format" });
    }
    
  } catch (error) {
    console.error("Error in token authentication:", error);
    res.status(500).json({ message: "Authentication error" });
  }
} 