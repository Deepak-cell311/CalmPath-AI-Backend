import "dotenv/config"
import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { therapeuticAI } from "./services/openai";
import multer from "multer";
import path from "path";
import express, { Request, Response } from "express";
import type { NextFunction } from "express";
import { createUser, getUserByEmail, User } from "./auth";
import { setupAuth, isAuthenticated, isAuthenticatedToken } from "./auth/middleware";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import bcrypt from "bcryptjs";
import z from "zod";
import { eq, and } from "drizzle-orm";
import Stripe from "stripe";

// memeory track route.ts
import {
    insertPatientSchema,
    insertStaffNoteSchema,
    insertMoodLogSchema,
    insertConversationSchema,
    insertTherapeuticPhotoSchema,
    Patient,
    users,
    StaffNote,
    Alert as AlertType,
    patients,
    memoryPhotos,
    facilities,
    insertMedicationSchema,
    facilityInvitePurchases,
    facilityInvitePackages,
    facilityInvites
} from "../shared/schema";
import { Methods } from "openai/resources/fine-tuning/methods";
import { randomUUID } from "crypto";
import { db } from "./db";
import cors from "cors";

// Helper function to determine the correct protocol
function getProtocol(req: Request): string {
    console.log('=== Protocol Detection Debug ===');
    console.log('req.protocol:', req.protocol);
    console.log('req.secure:', req.secure);
    console.log('req.headers[x-forwarded-proto]:', req.headers['x-forwarded-proto']);
    console.log('req.headers[x-forwarded-ssl]:', req.headers['x-forwarded-ssl']);
    console.log('req.headers[x-forwarded-for]:', req.headers['x-forwarded-for']);
    console.log('req.headers[host]:', req.headers['host']);
    console.log('req.headers[origin]:', req.headers['origin']);
    console.log('req.headers[referer]:', req.headers['referer']);
    console.log('All headers:', JSON.stringify(req.headers, null, 2));
    
    let protocol = req.protocol;
    
    if (req.headers['x-forwarded-proto']) {
        protocol = req.headers['x-forwarded-proto'] as string;
        console.log('Using X-Forwarded-Proto:', protocol);
    } else if (req.headers['x-forwarded-ssl'] === 'on') {
        protocol = 'https';
        console.log('Using X-Forwarded-SSL, setting protocol to https');
    } else if (req.secure) {
        protocol = 'https';
        console.log('Using req.secure, setting protocol to https');
    } else {
        console.log('Using default req.protocol:', protocol);
    }
    
    console.log('Final protocol determined:', protocol);
    
    // Fallback: If the request comes from an HTTPS origin, force HTTPS
    if (req.headers['origin'] && req.headers['origin'].startsWith('https://')) {
        console.log('Origin is HTTPS, forcing protocol to https');
        protocol = 'https';
    } else if (req.headers['referer'] && req.headers['referer'].startsWith('https://')) {
        console.log('Referer is HTTPS, forcing protocol to https');
        protocol = 'https';
    }
    
    console.log('Final protocol after fallback:', protocol);
    console.log('=== End Protocol Detection Debug ===');
    
    return protocol;
}

declare module 'express-session' {
    interface SessionData {
        user?: any; // Allow flexible user object for now
        testData?: any; // Allow test data for debugging
    }
}

declare global {
    namespace Express {
        interface Request {
            user?: any;
        }
    }
}

// Configure multer for photo uploads
const upload = multer({
    storage: multer.diskStorage({
        destination: (req: Request, file: Express.Multer.File, cb: (error: Error | null, destination: string) => void) => {
            const uploadPath = path.join(__dirname, 'uploads');
            
            // Ensure uploads directory exists
            const fs = require('fs');
            if (!fs.existsSync(uploadPath)) {
                fs.mkdirSync(uploadPath, { recursive: true });
            }
            
            cb(null, uploadPath);
        },
        filename: (req: Request, file: Express.Multer.File, cb: (error: Error | null, filename: string) => void) => {
            cb(null, `${Date.now()}-${file.originalname}`);
        }
    }),
    limits: {
        fileSize: 10 * 1024 * 1024, // 10MB limit
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);

        if (mimetype && extname) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'));
        }
    },
});

export async function registerRoutes(app: Express): Promise<Server> {

    // Add request logging middleware for debugging
    app.use((req, res, next) => {
        console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
        console.log('Headers:', JSON.stringify(req.headers, null, 2));
        next();
    });

    //  Test CORS
    const allowedOrigins = [
        'https://app.calmpath.ai',
        'http://localhost:3000',
        'https://calm-path-ai.vercel.app',
    ];

    app.use(cors({
        origin: (origin, callback) => {
            if (!origin || allowedOrigins.includes(origin)) {
                callback(null, true);
            } else {
                callback(new Error('Not allowed by CORS'));
            }
        },
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization']
    }));

    // --- Session: Use secure cookies and correct SameSite for production ---
    const PgSession = connectPgSimple(session);

    console.log('Setting up session store with DATABASE_URL:', process.env.DATABASE_URL ? 'Present' : 'Missing');

    // Create session store with error handling
    const sessionStore = new PgSession({
        conObject: {
            connectionString: process.env.DATABASE_URL,
            ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
        },
        tableName: 'auth_sessions',
        createTableIfMissing: true,
        pruneSessionInterval: 60, // Clean up expired sessions every 60 seconds
    });

    // Add error handling for session store
    sessionStore.on('connect', () => {
        console.log('✅ Session store connected successfully');
    });

    sessionStore.on('error', (error) => {
        console.error('❌ Session store error:', error);
    });

    // Test the session store connection
    sessionStore.on('disconnect', () => {
        console.log('Session store disconnected');
    });

    // Test session store operations
    const testSessionId = 'test-init-' + Date.now();
    const testData = {
        test: true,
        timestamp: Date.now(),
        cookie: {
            originalMaxAge: 24 * 60 * 60 * 1000,
            expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
            secure: false, // Temporarily disable for testing
            httpOnly: true,
            path: '/'
        }
    };

    console.log('Testing session store with session ID:', testSessionId);
    console.log('Test data:', JSON.stringify(testData, null, 2));

    sessionStore.set(testSessionId, testData, (err) => {
        if (err) {
            console.error('❌ Initial session store test failed:', err);
            console.error('Error details:', err.message);
        } else {
            console.log('✅ Initial session store test passed');
            // Clean up test session
            sessionStore.destroy(testSessionId, (destroyErr) => {
                if (destroyErr) {
                    console.error('❌ Failed to clean up test session:', destroyErr);
                } else {
                    console.log('✅ Test session cleaned up');
                }
            });
        }
    });

    app.use(session({
        store: sessionStore,
        secret: process.env.SESSION_SECRET || "repair-request-secret",
        resave: true, // Changed to true to ensure sessions are saved
        saveUninitialized: false,
        cookie: {
            secure: true, // Enable for cross-domain
            sameSite: "none", // Use none for cross-domain
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000, // 24 hours
            path: '/',
            domain: undefined // Let browser set domain automatically
        },
        name: 'calmpath.sid'
    }));

    // Add production debugging
    console.log('Session configuration:');
    console.log('- NODE_ENV:', process.env.NODE_ENV);
    console.log('- Cookie secure:', process.env.NODE_ENV === 'production');
    console.log('- Cookie sameSite:', process.env.NODE_ENV === 'production' ? "none" : "lax");
    console.log('- Session secret present:', !!process.env.SESSION_SECRET);

    // Add session error handling middleware
    app.use((err: any, req: Request, res: Response, next: NextFunction) => {
        if (err && err.code === 'ECONNREFUSED') {
            console.error('Database connection error:', err);
            res.status(500).json({ error: 'Database connection failed' });
        } else {
            next(err);
        }
    });

    // Add session debugging middleware
    app.use((req: Request, res: Response, next: NextFunction) => {
        console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - Session ID: ${req.sessionID}`);
        console.log(`[${new Date().toISOString()}] Session exists: ${!!req.session}`);
        console.log(`[${new Date().toISOString()}] Session user exists: ${!!req.session?.user}`);
        console.log(`[${new Date().toISOString()}] Session userId exists: ${!!req.session?.user?.userId}`);

        if (req.session?.user) {
            console.log(`[${new Date().toISOString()}] User in session: ${req.session.user.email}`);
            console.log(`[${new Date().toISOString()}] User ID in session: ${req.session.user.userId}`);
        }

        // Add response interceptor to log session changes
        const originalSend = res.send;
        res.send = function (data) {
            console.log(`[${new Date().toISOString()}] Response sent for ${req.method} ${req.path}`);
            if (req.session?.user) {
                console.log(`[${new Date().toISOString()}] Session user after response: ${req.session.user.email}`);
            }
            return originalSend.call(this, data);
        };

        next();
    });

    app.get("/api/health", (req, res) => {
        res.json({ status: "ok" });
    });

    // Debug session status
    app.get("/api/debug/session", (req, res) => {
        res.json({
            sessionId: req.sessionID,
            hasUser: !!req.session?.user,
            user: req.session?.user,
            cookie: req.session?.cookie,
            requestCookies: req.headers.cookie,
            headers: {
                origin: req.headers.origin,
                referer: req.headers.referer,
                host: req.headers.host,
                'user-agent': req.headers['user-agent']
            },
            environment: {
                NODE_ENV: process.env.NODE_ENV,
                cookieSecure: process.env.NODE_ENV === 'production',
                cookieSameSite: process.env.NODE_ENV === 'production' ? "none" : "lax"
            }
        });
    });

    // Check sessions in database
    app.get("/api/debug/sessions-in-db", async (req, res) => {
        try {
            const { Pool } = require('pg');
            const pool = new Pool({
                connectionString: process.env.DATABASE_URL,
                ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
            });

            const client = await pool.connect();
            const result = await client.query(`
                SELECT sid, sess, expire 
                FROM auth_sessions 
                ORDER BY expire DESC 
                LIMIT 10
            `);

            client.release();
            await pool.end();

            res.json({
                sessionCount: result.rows.length,
                sessions: result.rows.map((row: any) => ({
                    sid: row.sid,
                    hasUser: !!row.sess?.user,
                    userEmail: row.sess?.user?.email,
                    userId: row.sess?.user?.userId,
                    expire: row.expire
                })),
                currentSessionId: req.sessionID,
                currentSessionExists: !!req.session,
                currentSessionUser: !!req.session?.user,
                currentSessionUserId: req.session?.user?.userId
            });
        } catch (error: unknown) {
            console.error('Error checking sessions in DB:', error);
            res.status(500).json({
                error: 'Failed to check sessions in DB',
                details: error instanceof Error ? error.message : 'Unknown error'
            });
        }
    });

    // Test session storage
    app.post("/api/debug/test-session", (req, res) => {
        try {
            // Set a test session
            req.session.testData = {
                timestamp: new Date().toISOString(),
                message: "Test session data"
            };

            // Force save the session
            req.session.save((err) => {
                if (err) {
                    console.error('Error saving test session:', err);
                    res.status(500).json({ error: 'Failed to save session', details: err.message });
                } else {
                    console.log('Test session saved successfully');
                    res.json({
                        success: true,
                        sessionId: req.sessionID,
                        message: 'Test session saved'
                    });
                }
            });
        } catch (error) {
            console.error('Error in test session route:', error);
            res.status(500).json({ error: 'Test session failed' });
        }
    });

    // Check sessions in database
    app.get("/api/debug/sessions-in-db", async (req, res) => {
        try {
            const { Pool } = require('pg');
            const pool = new Pool({
                connectionString: process.env.DATABASE_URL,
                ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
            });

            const client = await pool.connect();
            const result = await client.query(`
                SELECT sid, sess, expire 
                FROM auth_sessions 
                ORDER BY expire DESC 
                LIMIT 10
            `);

            client.release();
            await pool.end();

            res.json({
                sessionCount: result.rows.length,
                sessions: result.rows.map((row: any) => ({
                    sid: row.sid,
                    hasUser: !!row.sess?.user,
                    userEmail: row.sess?.user?.email,
                    expire: row.expire
                }))
            });
        } catch (error: unknown) {
            console.error('Error checking sessions in DB:', error);
            res.status(500).json({
                error: 'Failed to check sessions in DB',
                details: error instanceof Error ? error.message : 'Unknown error'
            });
        }
    });

    // Test user session storage
    app.post("/api/debug/test-user-session", (req, res) => {
        try {
            // Set a test user session
            req.session.user = {
                id: 'test-user-' + Date.now(),
                email: 'test@example.com',
                firstName: 'Test',
                lastName: 'User',
                accountType: 'Facility Staff',
                userId: 'test-user-' + Date.now()
            };

            console.log('Setting test user session with ID:', req.sessionID);
            console.log('Test user session data:', req.session.user);

            // Force save the session
            req.session.save((err) => {
                if (err) {
                    console.error('Error saving test user session:', err);
                    res.status(500).json({ error: 'Failed to save session', details: err.message });
                } else {
                    console.log('Test user session saved successfully with ID:', req.sessionID);
                    res.json({
                        success: true,
                        sessionId: req.sessionID,
                        user: req.session.user,
                        message: 'Test user session saved'
                    });
                }
            });
        } catch (error) {
            console.error('Error in test user session route:', error);
            res.status(500).json({ error: 'Test user session failed' });
        }
    });

    // Test session retrieval
    app.get("/api/debug/test-session-retrieval", (req, res) => {
        try {
            console.log('Testing session retrieval for ID:', req.sessionID);
            console.log('Session exists:', !!req.session);
            console.log('Session user exists:', !!req.session?.user);
            console.log('Session user data:', req.session?.user);

            res.json({
                sessionId: req.sessionID,
                sessionExists: !!req.session,
                userExists: !!req.session?.user,
                userData: req.session?.user,
                message: 'Session retrieval test completed'
            });
        } catch (error) {
            console.error('Error in session retrieval test:', error);
            res.status(500).json({ error: 'Session retrieval test failed' });
        }
    });

    // Test cookie setting
    app.post("/api/debug/test-cookie", (req, res) => {
        try {
            console.log('Testing cookie setting');

            // Set a simple test cookie
            res.cookie('test-cookie', 'test-value-' + Date.now(), {
                httpOnly: true,
                secure: true,
                sameSite: 'none',
                maxAge: 24 * 60 * 60 * 1000
            });

            // Set session cookie manually
            res.cookie('calmpath.sid', 'test-session-' + Date.now(), {
                httpOnly: true,
                secure: true,
                sameSite: 'none',
                maxAge: 24 * 60 * 60 * 1000
            });

            res.json({
                success: true,
                message: 'Test cookies set',
                timestamp: Date.now()
            });
        } catch (error) {
            console.error('Error in cookie test:', error);
            res.status(500).json({ error: 'Cookie test failed' });
        }
    });

    // Check cookies
    app.get("/api/debug/check-cookies", (req, res) => {
        try {
            console.log('Checking cookies');
            console.log('Request cookies:', req.headers.cookie);

            res.json({
                requestCookies: req.headers.cookie,
                sessionId: req.sessionID,
                message: 'Cookie check completed'
            });
        } catch (error) {
            console.error('Error in cookie check:', error);
            res.status(500).json({ error: 'Cookie check failed' });
        }
    });

    // Token-based authentication (primary solution)
    app.post("/api/auth/login-token", async (req, res) => {
        try {
            const { accountType, email, password, inviteCode } = req.body;

            if (!email || !password || !accountType) {
                res.status(400).json({ error: 'Email, password, and accountType are required' });
                return;
            }

            // Find user
            const user = await getUserByEmail(email);

            if (!user) {
                res.status(404).json({ error: 'User not found' });
                return;
            }

            // Check account type match
            // Allow Family Members to login as Patient (for dual access)
            if (user.accountType !== accountType) {
                // Special case: Family Member can login as Patient
                if (!(user.accountType === "Family Member" && accountType === "Patient")) {
                    res.status(403).json({ error: 'Account type mismatch' });
                    return;
                }
            }

            // Verify password
            const isMatch = await bcrypt.compare(password, user.passwordHash);
            if (!isMatch) {
                res.status(401).json({ error: 'Invalid password' });
                return;
            }

            // Generate a simple token
            const tokenData = {
                userId: user.id,
                email: user.email,
                timestamp: Date.now()
            };
            console.log("Login endpoint: Token data:", tokenData);
            console.log("Login endpoint: Current time:", new Date().toISOString());
            console.log("Login endpoint: Timestamp value:", tokenData.timestamp);
            
            const token = Buffer.from(JSON.stringify(tokenData)).toString('base64');
            console.log("Login endpoint: Generated token:", token.substring(0, 20) + "...");

            res.json({
                success: true,
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.firstName,
                    firstName: user.firstName,
                    lastName: user.lastName,
                    accountType: user.accountType,
                    facilityId: user.facilityId,
                    usedInviteCode: user.usedInviteCode || false
                },
                token: token
            });
        } catch (error) {
            console.error('Token login error:', error);
            res.status(500).json({ error: 'Login failed' });
        }
    });

    // Token-based user verification
    app.get("/api/auth/user-token", async (req, res) => {
        try {
            const authHeader = req.headers.authorization;
            console.log("User-token endpoint: Auth header:", authHeader ? authHeader.substring(0, 20) + "..." : "none");

            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                console.log("User-token endpoint: No valid auth header");
                return res.status(401).json({ message: "No token provided" });
            }

            const token = authHeader.substring(7); // Remove 'Bearer '
            console.log("User-token endpoint: Token received:", token.substring(0, 20) + "...");

            try {
                const decoded = JSON.parse(Buffer.from(token, 'base64').toString());
                console.log("User-token endpoint: Token decoded:", decoded);
                console.log("User-token endpoint: Decoded token type:", typeof decoded);
                console.log("User-token endpoint: Decoded token keys:", Object.keys(decoded));
                console.log("User-token endpoint: Decoded timestamp:", decoded.timestamp);
                console.log("User-token endpoint: Decoded timestamp as date:", new Date(decoded.timestamp).toISOString());
                console.log("User-token endpoint: Current time:", new Date().toISOString());
                
                const userId = decoded.userId;
                console.log("User-token endpoint: Extracted userId:", userId, "type:", typeof userId);

                if (!userId) {
                    console.log("User-token endpoint: No userId in token");
                    return res.status(401).json({ message: "Invalid token" });
                }

                console.log("User-token endpoint: Looking up user:", userId);
                const user = await storage.getUser(userId);

                if (!user) {
                    console.log("User-token endpoint: User not found:", userId);
                    return res.status(404).json({ message: "User not found" });
                }

                console.log("User-token endpoint: User found:", user.id, user.email);
                res.json({
                    id: user.id,
                    email: user.email,
                    firstName: user.firstName,
                    lastName: user.lastName,
                    accountType: user.accountType,
                    facilityId: user.facilityId,
                    role: user.role || "staff"
                });

            } catch (tokenError) {
                console.error('Token decode error:', tokenError);
                res.status(401).json({ message: "Invalid token format" });
            }

        } catch (error) {
            console.error("Error fetching user with token:", error);
            res.status(500).json({ message: "Failed to fetch user" });
        }
    });

    // Set session manually for testing
    app.post("/api/debug/set-session", (req, res) => {
        try {
            // Set a test session
            req.session.user = {
                id: 'test-manual-' + Date.now(),
                email: 'test@example.com',
                firstName: 'Test',
                lastName: 'User',
                accountType: 'Facility Staff',
                userId: 'test-manual-' + Date.now()
            };

            console.log('Manually setting session with ID:', req.sessionID);
            console.log('Session data:', req.session.user);

            // Force save the session
            req.session.save((err) => {
                if (err) {
                    console.error('Error saving manual session:', err);
                    res.status(500).json({ error: 'Failed to save session', details: err.message });
                } else {
                    console.log('Manual session saved successfully with ID:', req.sessionID);

                    // Set a test cookie manually to see if it works
                    res.cookie('test-cookie', 'test-value', {
                        httpOnly: true,
                        secure: false,
                        sameSite: 'none',
                        maxAge: 24 * 60 * 60 * 1000
                    });

                    res.json({
                        success: true,
                        sessionId: req.sessionID,
                        user: req.session.user,
                        message: 'Manual session set successfully',
                        cookieSet: true
                    });
                }
            });
        } catch (error) {
            console.error('Error in manual session route:', error);
            res.status(500).json({ error: 'Manual session failed' });
        }
    });

    // Get current user
    app.get("/api/user/me", async (req, res) => {
        try {
            // Get user from session if available
            const userId = req.session?.user?.userId;

            if (userId) {
                // Fetch user from database
                const user = await storage.getUser(userId);
                if (user) {
                    res.json({
                        id: user.id,
                        firstName: user.firstName,
                        lastName: user.lastName,
                        email: user.email,
                        role: user.role || "staff"
                    });
                    return;
                }
            }

            // If no user in session or user not found, return 401
            res.status(401).json({ message: "User not authenticated" });
        } catch (error) {
            console.error("Error fetching user:", error);
            res.status(500).json({ message: "Failed to fetch user" });
        }
    });



    // Create test user endpoint (for development only)
    app.post("/api/auth/create-test-user", async (req, res) => {
        try {
            const { email, password, firstName, lastName } = req.body;

            if (!email || !password || !firstName || !lastName) {
                res.status(400).json({ message: "Email, password, firstName, and lastName are required" });
                return;
            }

            // Hash password
            const passwordHash = await bcrypt.hash(password, 10);

            // Create user
            const user = await createUser(
                email,
                `${firstName} ${lastName}`,
                'Facility Staff',
                passwordHash
            );

            res.json({
                id: user.id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                role: user.role
            });
        } catch (error) {
            console.error("Error creating test user:", error);
            res.status(500).json({ message: "Failed to create user" });
        }
    });

    // Logout endpoint
    app.post("/api/auth/logout", (req, res) => {
        try {
            // Destroy the session
            req.session.destroy((err) => {
                if (err) {
                    console.error("Error destroying session:", err);
                    res.status(500).json({ message: "Failed to logout" });
                } else {
                    res.json({ message: "Logged out successfully" });
                }
            });
        } catch (error) {
            console.error("Error during logout:", error);
            res.status(500).json({ message: "Failed to logout" });
        }
    });

    // Serve static files from the uploads directory
    const uploadsPath = path.join(__dirname, 'uploads');
    console.log('Setting up static file serving for uploads at:', uploadsPath);
    app.use('/uploads', express.static(uploadsPath));
    
    // Create a test file to verify static serving works
    const fs = require('fs');
    const testFilePath = path.join(uploadsPath, 'test.txt');
    if (!fs.existsSync(testFilePath)) {
        fs.writeFileSync(testFilePath, 'Static file serving test - ' + new Date().toISOString());
        console.log('Created test file for static serving:', testFilePath);
    }
    
    // Test endpoint to verify uploads directory
    app.get('/api/test-uploads', (req, res) => {
        const fs = require('fs');
        try {
            const files = fs.readdirSync(uploadsPath);
            res.json({ 
                uploadsPath, 
                files, 
                exists: fs.existsSync(uploadsPath),
                stats: fs.statSync(uploadsPath)
            });
        } catch (error: any) {
            res.status(500).json({ 
                error: error.message, 
                uploadsPath,
                exists: fs.existsSync(uploadsPath)
            });
        }
    });

    // Test endpoint to check static file serving
    app.get('/api/test-static/:filename', (req, res) => {
        const fs = require('fs');
        const filename = req.params.filename;
        const filePath = path.join(uploadsPath, filename);
        
        try {
            if (fs.existsSync(filePath)) {
                const stats = fs.statSync(filePath);
                res.json({
                    filename,
                    filePath,
                    exists: true,
                    size: stats.size,
                    isFile: stats.isFile(),
                    permissions: stats.mode.toString(8)
                });
            } else {
                res.json({
                    filename,
                    filePath,
                    exists: false,
                    uploadsPath,
                    uploadsExists: fs.existsSync(uploadsPath),
                    uploadsFiles: fs.existsSync(uploadsPath) ? fs.readdirSync(uploadsPath) : []
                });
            }
        } catch (error: any) {
            res.status(500).json({
                error: error.message,
                filename,
                filePath,
                uploadsPath
            });
        }
    });

    setupAuth(app);

    app.get('/api/auth/user', async (req: Request, res: Response): Promise<any> => {
        try {
            // Check if user is authenticated via session
            if (!req.session?.user?.userId) {
                return res.status(401).json({ message: "User not authenticated" });
            }

            const userId = req.session.user.userId;
            const user = await storage.getUser(userId);

            if (!user) {
                return res.status(404).json({ message: "User not found" });
            }

            res.json(user);
        } catch (error) {
            console.error("Error fetching user:", error);
            res.status(500).json({ message: "Failed to fetch user" });
        }
    });




    // =============== Patients API / Routes ================== //

    // Get all patients
    app.get("/api/patients", async (req, res) => {
        try {
            const { userId, facilityId } = req.query;
            const filters: { userId?: string; facilityId?: string } = {};

            if (userId && typeof userId === 'string') {
                filters.userId = userId;
            }

            if (facilityId && typeof facilityId === 'string') {
                filters.facilityId = facilityId;
            }

            const patients = await storage.getAllPatients(filters);
            res.json(patients);
        } catch (error) {
            console.error("Error fetching patients:", error);
            res.status(500).json({ message: "Failed to fetch patients" });
        }
    });

    // Get facility members (patients + invited family members)
    app.get("/api/facility/members", async (req, res) => {
        try {
            const { facilityId } = req.query;

            if (!facilityId || typeof facilityId !== 'string') {
                res.status(400).json({ message: "Facility ID is required" });
                return;
            }

            // Get patients from the patients table
            const facilityPatients = await db
                .select()
                .from(patients)
                .where(eq(patients.facilityId, facilityId));

            // Get family members from the users table who used invite codes for this facility
            const invitedFamilyMembers = await db
                .select()
                .from(users)
                .where(
                    and(
                        eq(users.facilityId, facilityId),
                        eq(users.usedInviteCode, true),
                        eq(users.accountType, 'Family Member')
                    )
                );

            // Combine and format the results
            const facilityMembers = [
                // Patients
                ...facilityPatients.map((patient: any) => ({
                    ...patient,
                    type: 'patient',
                    displayName: `${patient.firstName} ${patient.lastName}`,
                    status: patient.status || 'active'
                })),
                // Invited family members
                ...invitedFamilyMembers.map((user: any) => ({
                    id: user.id,
                    firstName: user.firstName,
                    lastName: user.lastName,
                    email: user.email,
                    phoneNumber: user.phoneNumber,
                    type: 'family_member',
                    displayName: `${user.firstName} ${user.lastName}`,
                    status: 'active',
                    usedInviteCode: user.usedInviteCode,
                    subscriptionStatus: user.subscriptionStatus
                }))
            ];

            res.json(facilityMembers);
        } catch (error) {
            console.error("Error fetching facility members:", error);
            res.status(500).json({ message: "Failed to fetch facility members" });
        }
    });

    // Get a specific patient by ID
    app.get("/api/patients/:id", async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            const patient = await storage.getPatient(id);
            if (!patient) {
                res.status(404).json({ message: "Patient not found" });
                return;
            }
            res.json(patient);
        } catch (error) {
            console.error("Error fetching patient:", error);
            res.status(500).json({ message: "Failed to fetch patient" });
        }
    });

    // Create a new patient
    app.post("/api/patients", async (req, res) => {
        try {
            // Handle the name field from frontend and split into firstName and lastName
            const { name, ...otherData } = req.body;

            let firstName = "";
            let lastName = "";

            if (name) {
                const nameParts = name.trim().split(' ');
                firstName = nameParts[0] || "";
                lastName = nameParts.slice(1).join(' ') || "";
            }

            // Create the data object with firstName and lastName
            const patientData = {
                firstName,
                lastName,
                ...otherData
            };

            const validatedData = insertPatientSchema.parse(patientData);
            const patient = await storage.createPatient(validatedData);
            res.json(patient);
        } catch (error) {
            console.error("Error creating patient:", error);
            res.status(400).json({ message: "Invalid patient data" });
        }
    });

    // Delete a patient by ID
    app.delete("/api/patients/:id", async (req, res) => {
        try {
            const id = parseInt(req.params.id);

            if (isNaN(id)) {
                res.status(400).json({ message: "Invalid patient ID" });
                return;
            }

            // Check if patient exists before deleting
            const existingPatient = await storage.getPatient(id);
            if (!existingPatient) {
                res.status(404).json({ message: "Patient not found" });
                return;
            }

            await storage.deletePatient(id);
            res.json({ message: "Patient deleted successfully" });
        } catch (error) {
            console.error("Error deleting patient:", error);
            res.status(500).json({ message: "Failed to delete patient" });
        }
    });

    // Update patient status (e.g., anxious, ok, good)
    app.patch("/api/patients/:id/status", async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            const { status } = req.body;

            if (!['anxious', 'ok', 'good'].includes(status)) {
                res.status(400).json({ message: "Invalid status" });
                return;
            }

            const patient = await storage.updatePatientStatus(id, status);
            const patientName = `${patient.firstName} ${patient.lastName}`;

            // Create alert for status changes to anxious
            if (status === 'anxious') {
                await storage.createAlert({
                    patientId: id,
                    type: 'status_change',
                    message: `${patientName}'s status changed to Anxious`,
                });
            }

            // Log mood change
            await storage.createMoodLog({
                patientId: id,
                status,
                loggedBy: req.user?.claims?.sub || 'system',
            });

            res.json(patient);
        } catch (error) {
            console.error("Error updating patient status:", error);
            res.status(500).json({ message: "Failed to update patient status" });
        }
    });

    // Update last interaction time for a patient
    app.patch("/api/patients/:id/interaction", async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            const patient = await storage.updatePatientInteraction(id);
            res.json(patient);
        } catch (error) {
            console.error("Error updating patient interaction:", error);
            res.status(500).json({ message: "Failed to update patient interaction" });
        }
    });

    // ==================== Staff notes routes ====================== //

    // Get all notes for a patient
    app.get("/api/patients/:id/notes", async (req, res) => {
        try {
            const patientId = parseInt(req.params.id);
            const notes = await storage.getPatientNotes(patientId);
            res.json(notes);
        } catch (error) {
            console.error("Error fetching patient notes:", error);
            res.status(500).json({ message: "Failed to fetch patient notes" });
        }
    });

    // Add a new staff note for a patient
    app.post("/api/patients/:id/notes", async (req, res) => {
        try {
            const patientId = parseInt(req.params.id);
            const staffId = req.session?.user?.userId || req.user?.claims?.sub;

            if (!staffId) {
                res.status(401).json({ message: "Unauthenticated: Missing staff ID" });
                return;
            }
            if (!patientId) {
                res.status(401).json({ message: "Unauthenticated: Missing patient ID" });
                return;
            }

            console.log("staffId: ", staffId);
            console.log("patientId: ", patientId);
            console.log("User: ", req.session.user);

            const validatedData = insertStaffNoteSchema.parse({
                ...req.body,
                patientId,
                staffId,
            });

            const note = await storage.createStaffNote(validatedData);
            res.json(note);
        } catch (error) {
            console.error("Error creating staff note:", error);
            res.status(400).json({ message: "Invalid note data" });
        }
    });

    // ====================== Mood history routes =========================== //

    // Get mood history for a patient (last N days)
    app.get("/api/patients/:id/mood-history", async (req, res) => {
        try {
            const patientId = parseInt(req.params.id);
            const days = parseInt(req.query.days as string) || 7;
            const history = await storage.getPatientMoodHistory(patientId, days);
            res.json(history);
        } catch (error) {
            console.error("Error fetching mood history:", error);
            res.status(500).json({ message: "Failed to fetch mood history" });
        }
    });

    // ====================== AI Conversation routes ========================= //
    app.post("/api/patients/:id/conversation", async (req, res) => {
        try {
            const patientId = parseInt(req.params.id);
            const { message } = req.body;
            const staffId = req.user?.claims?.sub;

            const patient = await storage.getPatient(patientId);
            if (!patient) {
                res.status(404).json({ message: "Patient not found" });
                return;
            }

            // Get recent notes for context
            const recentNotes = await storage.getPatientNotes(patientId);
            const noteTexts = recentNotes.slice(0, 3).map((note: StaffNote) => note.content);

            const photos = await storage.getPatientPhotos(patientId);
            const photoDescriptions = photos.map(photo => photo.description || photo.category).filter(Boolean) as string[];

            const patientName = `${patient.firstName} ${patient.lastName}`;

            const context = {
                patientName: patientName,
                patientAge: typeof patient.age === 'number' ? patient.age : 0,
                currentMood: patient.status,
                recentNotes: noteTexts,
                therapeuticPhotos: photoDescriptions,
            };

            const aiResponse = await therapeuticAI.generateResponse(message, context);

            // Update patient interaction time
            await storage.updatePatientInteraction(patientId);

            const conversationData = insertConversationSchema.parse({
                patientId,
                staffId,
                transcript: `Patient: ${message}\nAI: ${aiResponse.message}`,
                sentiment: aiResponse.sentiment,
                userMessage: message,
                aiResponse: aiResponse.message,
            });
            const conversation = await storage.createConversation(conversationData);

            if (aiResponse.suggestedMood !== patient.status) {
                await storage.updatePatientStatus(patientId, aiResponse.suggestedMood);

                // Create alert if mood worsened
                if (aiResponse.suggestedMood === 'anxious') {
                    await storage.createAlert({
                        patientId,
                        type: 'status_change',
                        message: `${patientName}'s mood detected as anxious during AI conversation`,
                    });
                }
            }

            res.json({
                response: aiResponse.message,
                sentiment: aiResponse.sentiment,
                needsStaffAttention: aiResponse.needsStaffAttention,
                conversationId: conversation.id,
            });
        } catch (error) {
            console.error("Error processing AI conversation:", error);
            res.status(500).json({ message: "Failed to process conversation" });
        }
    });

    // ============================ Therapeutic photos routes ======================= //

    // Get all therapeutic photos for a patient
    app.get("/api/patients/:id/photos", async (req, res) => {
        try {
            const patientId = parseInt(req.params.id);
            const photos = await storage.getPatientPhotos(patientId);
            res.json(photos);
        } catch (error) {
            console.error("Error fetching therapeutic photos:", error);
            res.status(500).json({ message: "Failed to fetch photos" });
        }
    });


    app.post("/api/family/memoryPhotos", upload.single("photo"), async (req: Request, res: Response): Promise<any> => {
        try {
            const uploadedBy = req.user?.claims?.sub;

            if (!req.file) {
                return res.status(400).json({ message: "No photo uploaded" });
            }

            console.log("File uploaded successfully:", req.file.filename, "to", req.file.path);

            const photoUrl = `/uploads/${req.file.filename}`;

            // Determine the correct protocol for production
            const protocol = getProtocol(req);
            
            console.log("Request protocol:", req.protocol);
            console.log("X-Forwarded-Proto:", req.headers['x-forwarded-proto']);
            console.log("X-Forwarded-SSL:", req.headers['x-forwarded-ssl']);
            console.log("Request secure:", req.secure);
            console.log("Final protocol:", protocol);
            console.log("Request host:", req.get("host"));
            console.log("Request headers:", req.headers);
            console.log("Full URL being constructed:", `${protocol}://${req.get("host")}${photoUrl}`);

            const schema = z.object({
                file: z.string().url(),
                photoname: z.string().optional(),
                description: z.string().optional(),
                tags: z.array(z.string()).optional(),
                contextAndStory: z.string().optional(),
            });

            const validatedData = schema.parse({
                file: `${protocol}://${req.get("host")}${photoUrl}`,
                photoname: req.body.photoname,
                description: req.body.description,
                tags: req.body.tags ? JSON.parse(req.body.tags) : [],
                contextAndStory: req.body.contextAndStory,
            });

            // TODO: Save `validatedData` to DB here
            await db.insert(memoryPhotos).values({
                // uploadedBy,
                photoname: validatedData.photoname || "",
                description: validatedData.description || "",
                contextAndStory: validatedData.contextAndStory || "",
                file: validatedData.file,
                tags: validatedData.tags,
            });

            return res.status(200).json({ message: "Photo uploaded", data: validatedData });
        } catch (error: any) {
            console.error("Error uploading photo:", error);
            return res.status(500).json({ message: "Failed to upload photo", error: error.message });
        }
    }
    );

    app.get("/api/family/memoryPhotos", async (req: Request, res: Response): Promise<any> => {
        try {
            const uploadedBy = req.user?.claims?.sub;

            // Query memory photos by uploader
            const photos = await db
                .select()
                .from(memoryPhotos)
            // .where(memoryPhotos.uploadedBy, "=", uploadedBy);

            // Format and return
            const formatted = photos.map((photo) => ({
                id: photo.id,
                photoname: photo.photoname,
                description: photo.description,
                tags: photo.tags,
                contextAndStory: photo.contextAndStory,
                file: photo.file,
                created_at: photo.createdAt, // adjust field if necessary
            }));

            return res.status(200).json({ data: formatted });
        } catch (error: any) {
            console.error("Error fetching memory photos:", error);
            return res.status(500).json({ message: "Failed to fetch memory photos", error: error.message });
        }
    });

    app.delete("/api/family/memoryPhotos/:id", async (req: Request, res: Response): Promise<any> => {
        try {
            const id = parseInt(req.params.id);
            console.log('Attempting to delete photo with ID:', id);
            
            if (!id || isNaN(id)) {
                return res.status(400).json({ message: "Invalid id provided" });
            }
            
            // Find the photo to get the file path
            const photo = await db.query.memoryPhotos.findFirst({ 
                where: (photo, { eq }) => eq(photo.id, id) 
            });
            
            console.log('Found photo:', photo);
            
            if (!photo) {
                return res.status(404).json({ message: "Photo not found" });
            }
            
            // Delete from DB first
            await db.delete(memoryPhotos).where(eq(memoryPhotos.id, id));
            console.log('Photo deleted from database');
            
            // Delete file from disk
            if (photo.file) {
                const fs = require('fs');
                const path = require('path');
                
                // Extract filename from the full URL
                const urlParts = photo.file.split('/');
                const filename = urlParts[urlParts.length - 1];
                const filePath = path.join(__dirname, 'uploads', filename);
                
                console.log('Attempting to delete file:', filePath);
                console.log('File URL from DB:', photo.file);
                console.log('Extracted filename:', filename);
                
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath);
                    console.log('File deleted successfully:', filePath);
                } else {
                    console.log('File not found for deletion:', filePath);
                    // Try alternative path
                    const altPath = path.join(__dirname, 'uploads', path.basename(photo.file));
                    if (fs.existsSync(altPath)) {
                        fs.unlinkSync(altPath);
                        console.log('File deleted from alternative path:', altPath);
                    } else {
                        console.log('File not found in alternative path either:', altPath);
                    }
                }
            }
            
            return res.status(200).json({ message: "Photo deleted successfully" });
        } catch (error: any) {
            console.error("Error deleting memory photo:", error);
            return res.status(500).json({ 
                message: "Failed to delete memory photo", 
                error: error.message,
                stack: error.stack 
            });
        }
    });

    app.post("/api/patients/:id/photos", upload.single('photo'), async (req: Request, res: Response) => {
        try {
            const patientId = parseInt(req.params.id);
            const uploadedBy = req.user?.claims?.sub;

            if (!req.file) {
                res.status(400).json({ message: "No photo uploaded" });
                return;
            }

            const photoUrl = `/uploads/${req.file.filename}`;

            const validatedData = insertTherapeuticPhotoSchema.parse({
                patientId,
                url: photoUrl,
                description: req.body.description,
                category: req.body.category,
                uploadedBy,
            });

            const photo = await storage.createTherapeuticPhoto(validatedData);
            res.json(photo);
        } catch (error) {
            console.error("Error uploading therapeutic photo:", error);
            res.status(400).json({ message: "Failed to upload photo" });
        }
    });

    // Delete a photo by ID
    app.delete("/api/photos/:id", async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            await storage.deleteTherapeuticPhoto(id);
            res.json({ message: "Photo deleted successfully" });
        } catch (error) {
            console.error("Error deleting photo:", error);
            res.status(500).json({ message: "Failed to delete photo" });
        }
    });

    // ===================== Alerts routes ======================== //

    // Get all unread alerts
    app.get("/api/alerts", async (req, res) => {
        try {
            const alerts = await storage.getUnreadAlerts();
            res.json(alerts);
        } catch (error) {
            console.error("Error fetching alerts:", error);
            res.status(500).json({ message: "Failed to fetch alerts" });
        }
    });

    // Mark alert as read
    app.patch("/api/alerts/:id/read", async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            await storage.markAlertAsRead(id);
            res.json({ message: "Alert marked as read" });
        } catch (error) {
            console.error("Error marking alert as read:", error);
            res.status(500).json({ message: "Failed to mark alert as read" });
        }
    });

    // ============================ Analytics routes ==================== //


    // Get patient counts per status (e.g., anxious, ok, good)
    app.get("/api/analytics/status-counts", async (req, res) => {
        try {
            const counts = await storage.getPatientStatusCounts();
            res.json(counts);
        } catch (error) {
            console.error("Error fetching status counts:", error);
            res.status(500).json({ message: "Failed to fetch analytics" });
        }
    });

    // Background task to check for inactive patients
    setInterval(async () => {
        try {
            const inactivePatients = await storage.getPatientsWithNoRecentActivity(4);

            for (const patient of inactivePatients) {
                // Check if alert already exists for this patient
                const existingAlerts = await storage.getUnreadAlerts();
                const hasInactivityAlert = existingAlerts.some(
                    (alert: AlertType) => alert.patientId === patient.id && alert.type === 'no_activity'
                );

                if (!hasInactivityAlert) {
                    const patientName = `${patient.firstName} ${patient.lastName}`;
                    await storage.createAlert({
                        patientId: patient.id,
                        type: 'no_activity',
                        message: `${patientName} has had no activity for over 4 hours`,
                    });
                }
            }
        } catch (error) {
            console.error("Error checking for inactive patients:", error);
        }
    }, 15 * 60 * 1000);

    // Individual user login (session-based)

    // Improved signup route with Zod validation and better error handling
    const signupSchema = z.object({
        accountType: z.enum(["Patient", "Family Member", "Facility Staff"]),
        firstName: z.string().min(1, "First name is required"),
        lastName: z.string().min(1, "Last name is required"),
        email: z.string().email("Invalid email address"),
        phoneNumber: z.string().min(10, "Phone number is required"),
        password: z.string().min(6, "Password must be at least 6 characters"),
        confirmPassword: z.string().min(6, "Confirm password is required"),
        relationToPatient: z.string().optional(),
        // patientAccessCode: z.string().optional(),
        // facilityId: z.union([z.string(), z.number()]).optional(),
        facilityName: z.string().optional(),
        age: z.number().optional(),
        roomNumber: z.string().optional(),
        care_level: z.string().optional(),
    }).refine((data) => data.password === data.confirmPassword, {
        message: "Passwords do not match",
        path: ["confirmPassword"],
    });

    app.post("/api/auth/signup", async (req, res): Promise<any> => {
        const parsed = signupSchema.safeParse(req.body);
        if (!parsed.success) {
            return res.status(400).json({
                error: {
                    field: parsed.error.errors[0].path[0],
                    message: parsed.error.errors[0].message,
                }
            });
        }

        const {
            accountType,
            firstName,
            lastName,
            phoneNumber,
            email,
            password,
            relationToPatient,
            // patientAccessCode,
            // facilityId,
            facilityName,
            roomNumber,
            care_level,
        } = parsed.data;

        const normalizedPhone = phoneNumber.trim();
        const passwordHash = await bcrypt.hash(password, 10);
        const userId = randomUUID();
        const emailCheck = email.trim();

        try {
            // Check if user phone number already exists
            const existing = await db.select().from(users).where(eq(users.phoneNumber, normalizedPhone));
            if (existing.length > 0) {
                return res.status(409).json({
                    message: "Phone number already registered"
                });
            }

            // Check user email address already exists
            const existingEmail = await db.select().from(users).where(eq(users.email, emailCheck))
            if (existingEmail.length > 0) {
                return res.status(409).json({
                    message: "Email Id already registered"
                })
            }

            // Facility Staff logic
            let facilityStaffFacilityId = null;
            if (accountType === "Facility Staff") {
                if (!facilityName) {
                    return res.status(400).json({
                        message: "Facility Name is required for Facility Staff"
                    });
                }

                // Create a new facility for the staff member
                const facility = await storage.createFacility({
                    name: facilityName,
                    address: "",
                    phone: normalizedPhone,
                    adminEmail: email,
                    tagline: "",
                    logoUrl: "",
                    brandColor: "#3B82F6",
                    monthlyPrice: "25",
                    promoCode: "",
                    subscriptionTier: "premium"
                });

                facilityStaffFacilityId = facility.id;

                // Create default invite packages for the new facility
                await storage.createFacilityInvitePackage({
                    facilityId: facility.id,
                    packageName: "Starter Pack",
                    inviteCount: 10,
                    priceInCents: 2500, // $25
                    isActive: true
                });

                await storage.createFacilityInvitePackage({
                    facilityId: facility.id,
                    packageName: "Professional Pack",
                    inviteCount: 25,
                    priceInCents: 5000, // $50
                    isActive: true
                });

                await storage.createFacilityInvitePackage({
                    facilityId: facility.id,
                    packageName: "Enterprise Pack",
                    inviteCount: 100,
                    priceInCents: 15000, // $150
                    isActive: true
                });
            }

            // Base user insert
            const [user] = await db
                .insert(users)
                .values({
                    id: userId,
                    accountType,
                    firstName,
                    lastName,
                    phoneNumber: normalizedPhone,
                    email,
                    passwordHash,
                    role:
                        accountType === "Patient"
                            ? "patient"
                            : accountType === "Family Member"
                                ? "family"
                                : "caregiver",
                    relationToPatient: accountType === "Family Member" ? relationToPatient : null,
                    patientAccessCode: null,
                    facilityStaffFacilityId: accountType === "Facility Staff" ? facilityStaffFacilityId : null,
                    isActive: true,
                    createdAt: new Date(),
                    updatedAt: new Date(),
                })
                .returning();

            // If patient, insert into patients table
            if (accountType === "Patient") {
                // Only allow valid care_level values
                const validCareLevels = ["low", "medium", "high"];
                const patientData: any = {
                    userId: userId,
                    facilityId: null, // Will be set when they use an invite code
                    firstName,
                    lastName,
                    status: "ok",
                    isActive: true,
                    createdAt: new Date(),
                    updatedAt: new Date(),
                };
                if (roomNumber) patientData.roomNumber = roomNumber;
                if (typeof care_level === "string" && validCareLevels.includes(care_level)) patientData.care_level = care_level;
                await db.insert(patients).values(patientData);
            }

            return res.status(201).json({
                message: "Signup successful",
                user,
            });
        } catch (err) {
            console.error("Signup error:", err);
            return res.status(500).json({ message: "Server error" });
        }
    });


    app.post('/api/auth/login', async (req, res) => {
        try {
            const { accountType, email, password, inviteCode } = req.body;

            if (!email || !password || !accountType) {
                res.status(400).json({ error: 'Email, password, and accountType are required' });
                return;
            }

            // Find user
            const user = await getUserByEmail(email);

            if (!user) {
                res.status(404).json({ error: 'User not found' });
                return;
            }

            // Check account type match
            if (user.accountType !== accountType) {
                res.status(403).json({ error: 'Account type mismatch' });
                return;
            }

            // Verify password
            const isMatch = await bcrypt.compare(password, user.passwordHash);
            if (!isMatch) {
                res.status(401).json({ error: 'Invalid password' });
                return;
            }

            // Handle invite code if provided
            if (inviteCode && inviteCode.trim()) {
                try {
                    // First, find the invite to get the correct facility
                    const [invite] = await db.select().from(facilityInvites).where(eq(facilityInvites.inviteCode, inviteCode.trim()));
                    
                    if (!invite) {
                        res.status(400).json({ error: 'Invalid invite code' });
                        return;
                    }

                    if (invite.status !== 'unused') {
                        res.status(400).json({ error: 'Invite code has already been used' });
                        return;
                    }

                    if (invite.expiresAt && new Date() > invite.expiresAt) {
                        res.status(400).json({ error: 'Invite code has expired' });
                        return;
                    }

                    // Get the facility from the invite
                    const [facility] = await db.select().from(facilities).where(eq(facilities.id, invite.facilityId));
                    
                    if (!facility) {
                        res.status(500).json({ error: 'Facility not found for this invite' });
                        return;
                    }

                    console.log('Using invite code for facility:', facility.id, 'with user:', user.id);

                    // Use the invite code
                    const inviteResult = await storage.useFacilityInvite(inviteCode.trim(), facility.id, {
                        email: user.email || undefined,
                        phone: user.phoneNumber || undefined,
                        name: `${user.firstName} ${user.lastName}`
                    });

                    if (!inviteResult.success) {
                        res.status(400).json({ error: inviteResult.message || 'Invalid invite code' });
                        return;
                    }

                    // Update user to mark that they used an invite code and link to facility
                    await db.update(users)
                        .set({
                            usedInviteCode: true,
                            facilityId: facility.id,
                            updatedAt: new Date()
                        })
                        .where(eq(users.id, user.id));

                    console.log("User used invite code successfully:", user.id, "for facility:", facility.id);
                } catch (error) {
                    console.error('Error processing invite code:', error);
                    res.status(500).json({ error: 'Failed to process invite code' });
                    return;
                }
            }

            // Save session
            req.session.user = {
                ...user,
                userId: user.id,
            };

            console.log("Session set:", req.session.user);

            // Force save the session and wait for it to complete
            req.session.save((err) => {
                if (err) {
                    console.error('Error saving session:', err);
                    res.status(500).json({ error: 'Failed to save session' });
                } else {
                    console.log('Session saved successfully');
                    res.json({
                        success: true,
                        user: {
                            id: user.id,
                            email: user.email,
                            name: user.firstName,
                            accountType: user.accountType,
                            usedInviteCode: user.usedInviteCode || false
                        }
                    });
                }
            });
        } catch (error) {
            console.error('Login error:', error);
            res.status(500).json({ error: 'Login failed' });
        }
    });


    app.post('/api/auth/facility/login', async (req, res) => {
        try {
            const { email, facilityName, adminName } = req.body;

            if (!email || !facilityName || !adminName) {
                res.status(400).json({ error: 'Email, facility name, and admin name are required' });
                return;
            }

            let user = await getUserByEmail(email);

            // If not, create new facility user
            if (!user) {
                const passwordHash = await bcrypt.hash(randomUUID(), 10);
                user = await createUser(email, `${adminName} (${facilityName})`, 'Facility Staff', passwordHash);
                console.log('Created new facility user:', user.id);
            } else if (user.accountType !== 'Facility Staff') {
                res.status(400).json({ error: 'Email is associated with an individual account' });
                return;
            }

            // Store user in session
            req.session.user = {
                ...user,
                userId: user.id,
            };

            // Force save the session and wait for it to complete
            req.session.save((err) => {
                if (err) {
                    console.error('Error saving session:', err);
                    res.status(500).json({ error: 'Failed to save session' });
                } else {
                    console.log('Session saved successfully');
                    res.json({
                        success: true,
                        user: {
                            id: user.id,
                            email: user.email,
                            name: user.firstName,
                            accountType: user.accountType
                        }
                    });
                }
            });
        } catch (error) {
            console.error('Facility login error:', error);
            res.status(500).json({ error: 'Login failed' });
        }
    });

    // Get current user
    app.get('/api/auth/currentUser', async (req, res) => {
        const userId = req.session?.user?.userId;

        if (userId) {
            // Fetch the latest user data from database to get the usedInviteCode status
            try {
                const currentUser = await storage.getUser(userId);
                if (currentUser) {
                    res.json({
                        id: currentUser.id,
                        email: currentUser.email,
                        name: currentUser.firstName,
                        accountType: currentUser.accountType,
                        usedInviteCode: currentUser.usedInviteCode || false
                    });
                } else {
                    res.status(404).json({ error: 'User not found in database' });
                }
            } catch (error) {
                console.error("Error fetching current user:", error);
                res.status(500).json({ error: 'Failed to fetch user data' });
            }
        } else {
            res.status(401).json({ error: 'Not authenticated' });
        }
    });

    // Token-based current user
    app.get('/api/auth/currentUser-token', isAuthenticatedToken, async (req, res) => {
        try {
            const userId = req.user?.userId;

            if (!userId) {
                return res.status(401).json({ error: 'No user ID in token' });
            }

            const currentUser = await storage.getUser(userId);
            if (currentUser) {
                res.json({
                    id: currentUser.id,
                    email: currentUser.email,
                    name: currentUser.firstName,
                    accountType: currentUser.accountType,
                    usedInviteCode: currentUser.usedInviteCode || false
                });
            } else {
                res.status(404).json({ error: 'User not found in database' });
            }
        } catch (error) {
            console.error("Error fetching current user with token:", error);
            res.status(500).json({ error: 'Failed to fetch user data' });
        }
    });

    // Invite-based login (password-less)
    app.post('/api/auth/invite-login', async (req, res) => {
        try {
            const { email, inviteCode, accountType } = req.body;

            console.log('Invite login attempt:', { email, inviteCode, accountType });

            if (!email || !inviteCode || !accountType) {
                res.status(400).json({ error: 'Email, inviteCode, and accountType are required' });
                return;
            }

            // Find user by email
            const user = await getUserByEmail(email);

            if (!user) {
                res.status(404).json({ error: 'User not found. Please sign up first.' });
                return;
            }

            console.log('User found:', { userId: user.id, accountType: user.accountType });

            // Check account type match
            // Allow Family Members to login as Patient (for dual access)
            if (user.accountType !== accountType) {
                // Special case: Family Member can login as Patient
                if (!(user.accountType === "Family Member" && accountType === "Patient")) {
                    res.status(403).json({ error: 'Account type mismatch' });
                    return;
                }
            }

            console.log('Validating invite code:', inviteCode.trim());

            // First, find the invite to get the correct facility
            const [invite] = await db.select().from(facilityInvites).where(eq(facilityInvites.inviteCode, inviteCode.trim()));
            
            console.log('Invite lookup result:', invite ? { 
                id: invite.id, 
                status: invite.status, 
                facilityId: invite.facilityId,
                expiresAt: invite.expiresAt 
            } : 'Not found');
            
            if (!invite) {
                res.status(400).json({ error: 'Invalid invite code' });
                return;
            }

            if (invite.status !== 'unused') {
                res.status(400).json({ error: 'Invite code has already been used' });
                return;
            }

            if (invite.expiresAt && new Date() > invite.expiresAt) {
                res.status(400).json({ error: 'Invite code has expired' });
                return;
            }

            // Get the facility from the invite
            const [facility] = await db.select().from(facilities).where(eq(facilities.id, invite.facilityId));
            
            console.log('Facility lookup result:', facility ? { 
                id: facility.id, 
                name: facility.name 
            } : 'Not found');
            
            if (!facility) {
                res.status(500).json({ error: 'Facility not found for this invite' });
                return;
            }

            console.log('Using invite code for facility:', facility.id, 'with user:', user.id);

            // Use the invite code
            const inviteResult = await storage.useFacilityInvite(inviteCode.trim(), facility.id, {
                email: user.email || undefined,
                phone: user.phoneNumber || undefined,
                name: `${user.firstName} ${user.lastName}`
            });

            console.log('Invite usage result:', inviteResult);

            if (!inviteResult.success) {
                res.status(400).json({ error: inviteResult.message || 'Invalid invite code' });
                return;
            }

            // Update user to mark that they used an invite code, link to facility, and set subscription as active
            await db.update(users)
                .set({
                    usedInviteCode: true,
                    facilityId: facility.id,
                    subscriptionStatus: 'active',
                    updatedAt: new Date()
                })
                .where(eq(users.id, user.id));

            // Generate a simple token
            const tokenData = {
                userId: user.id,
                email: user.email,
                timestamp: Date.now()
            };
            console.log("Invite login endpoint: Token data:", tokenData);
            console.log("Invite login endpoint: Current time:", new Date().toISOString());
            console.log("Invite login endpoint: Timestamp value:", tokenData.timestamp);
            
            const token = Buffer.from(JSON.stringify(tokenData)).toString('base64');
            console.log("Invite login endpoint: Generated token:", token.substring(0, 20) + "...");

            console.log("Invite login successful:", user.id, "for facility:", facility.id);

            res.json({
                success: true,
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.firstName,
                    accountType: user.accountType,
                    usedInviteCode: true,
                    facilityId: facility.id,
                    subscriptionStatus: 'active'
                },
                token: token,
                facility: {
                    id: facility.id,
                    name: facility.name
                }
            });
        } catch (error) {
            console.error('Invite login error:', error);
            res.status(500).json({ error: 'Invite login failed' });
        }
    });

    // Logout user (destroys session)
    app.post('/api/auth/logout', (req, res) => {
        req.session.destroy((err: any) => {
            if (err) {
                console.error('Logout error:', err);
                res.status(500).json({ error: 'Logout failed' });
                return;
            }
            res.json({ success: true });
        });
    });

    // ===================== AI Chat API ===================== //
    app.post("/api/chat", async (req: Request, res: Response): Promise<any> => {
        try {
            const { message, conversationHistory } = req.body;
            if (!message) {
                return res.status(400).json({ message: "Message is required" });
            }

            const aiResult = await therapeuticAI.generateResponse(message, conversationHistory);

            let photos: any[] = [];
            const messageLower = message.toLowerCase();
            if (
                messageLower.includes("home") ||
                messageLower.includes("house") ||
                (messageLower.includes("miss") && messageLower.includes("home")) ||
                messageLower.includes("wish i could see")
            ) {
                const queryTags = ["home", "house", "family"];
                const dbPhotos = await db.select().from(memoryPhotos);
                photos = dbPhotos.filter(photo =>
                    Array.isArray(photo.tags) && photo.tags.some((tag: string) => queryTags.includes(tag.toLowerCase()))
                );
            }

            res.json({
                response: aiResult.message,
                photos,
            });
        } catch (error: any) {
            console.error("Error in /api/chat:", error);
            res.status(500).json({ message: "Failed to get AI response", error: error.message });
        }
    });

    // Get all medications for a patient
    app.get("/api/patients/:id/medications", async (req, res) => {
        try {
            const patientId = parseInt(req.params.id);
            const meds = await storage.getMedications(patientId);
            res.json(meds);
        } catch (error) {
            console.error("Error fetching medications:", error);
            res.status(500).json({ message: "Failed to fetch medications" });
        }
    });

    // Add a new medication for a patient
    app.post("/api/patients/:id/medications", async (req, res) => {
        try {
            const patientId = parseInt(req.params.id);
            const validatedData = insertMedicationSchema.parse({ ...req.body, patientId });
            const med = await storage.createMedication(validatedData);
            res.json(med);
        } catch (error) {
            console.error("Error adding medication:", error);
            res.status(400).json({ message: "Invalid medication data" });
        }
    });

    // Delete a medication
    app.delete("/api/medications/:id", async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            await storage.deleteMedication(id);
            res.json({ message: "Medication deleted successfully" });
        } catch (error) {
            console.error("Error deleting medication:", error);
            res.status(500).json({ message: "Failed to delete medication" });
        }
    });


    // ===================== Stripe routes ===================== //

    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
        apiVersion: '2025-06-30.basil',
    });

    // Create Checkout Session
    app.post("/api/billing/checkout-session", isAuthenticatedToken, async (req: Request, res: Response): Promise<any> => {
        try {
            const { priceId, customerEmail, metadata, couponId } = req.body;
            const userId = req.user?.userId;

            if (!priceId || !customerEmail) {
                return res.status(400).json({ message: "Price ID and customer email are required" });
            }

            const sessionParams: Stripe.Checkout.SessionCreateParams = {
                mode: "subscription",
                line_items: [{ price: priceId, quantity: 1 }],
                customer_email: customerEmail,
                metadata: {
                    ...metadata,
                    userId: userId,
                },
                success_url: `${process.env.API_URL}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
                cancel_url: `${process.env.API_URL}/billing/cancel`,
                allow_promotion_codes: true,
                subscription_data: {
                    metadata: {
                        userId: userId,
                    },
                },
            };

            // Add coupon if provided
            if (couponId) {
                sessionParams.discounts = [{ coupon: couponId }];
            }

            const session = await stripe.checkout.sessions.create(sessionParams);

            res.json({ url: session.url, sessionId: session.id });
        } catch (err: any) {
            console.error("Checkout session error:", err);
            if (err && err.raw) {
                console.error("Stripe error details:", err.raw);
            }
            res.status(500).json({
                message: "Failed to create session",
                error: err.message || JSON.stringify(err)
            });
        }
    });

    // Create Customer Portal Session
    app.post("/api/billing/portal-session", isAuthenticatedToken, async (req: Request, res: Response): Promise<any> => {
        try {
            const userId = req.user?.userId;

            // Get user from database to find Stripe customer ID
            const user = await storage.getUser(userId);

            if (!user?.stripeCustomerId) {
                return res.status(404).json({ message: "No billing account found" });
            }

            const session = await stripe.billingPortal.sessions.create({
                customer: user.stripeCustomerId,
                return_url: `${process.env.API_URL}/billing/account`,
            });

            res.json({ url: session.url });
        } catch (err: any) {
            console.error("Portal session error:", err);
            res.status(500).json({
                message: "Failed to create portal session",
                error: err.message
            });
        }
    });

    // Get subscription details
    app.get("/api/billing/subscription", isAuthenticatedToken, async (req: Request, res: Response): Promise<any> => {
        try {
            const userId = req.user?.userId;
            const user = await storage.getUser(userId);

            // Check if user has a Stripe subscription
            if (user?.stripeSubscriptionId) {
                const subscription = await stripe.subscriptions.retrieve(user.stripeSubscriptionId);

                res.json({
                    subscription: {
                        id: subscription.id,
                        status: subscription.status,
                        currentPeriodStart: (subscription as any).current_period_start,
                        currentPeriodEnd: (subscription as any).current_period_end,
                        cancelAtPeriodEnd: (subscription as any).cancel_at_period_end,
                        items: subscription.items.data.map(item => ({
                            id: item.id,
                            price: {
                                id: item.price.id,
                                unit_amount: item.price.unit_amount,
                                currency: item.price.currency,
                                recurring: item.price.recurring,
                            },
                            quantity: item.quantity,
                        })),
                    },
                });
            }
            // Check if user used an invite code and has active subscription
            else if (user?.usedInviteCode && user?.subscriptionStatus === 'active') {
                res.json({
                    subscription: {
                        id: 'invite-access',
                        status: 'active',
                        type: 'invite',
                        message: 'Access granted via facility invite code'
                    },
                });
            }
            else {
                return res.status(404).json({ message: "No active subscription found" });
            }
        } catch (err: any) {
            console.error("Subscription retrieval error:", err);
            res.status(500).json({
                message: "Failed to retrieve subscription",
                error: err.message
            });
        }
    });

    // Cancel subscription
    app.post("/api/billing/cancel-subscription", isAuthenticatedToken, async (req: Request, res: Response): Promise<any> => {
        try {
            const userId = req.user?.userId;
            const user = await storage.getUser(userId);

            if (!user?.stripeSubscriptionId) {
                return res.status(404).json({ message: "No active subscription found" });
            }

            const subscription = await stripe.subscriptions.update(user.stripeSubscriptionId, {
                cancel_at_period_end: true,
            });

            await storage.updateUserSubscriptionStatus(userId, subscription.status);

            res.json({
                message: "Subscription will be canceled at the end of the current period",
                subscription: {
                    id: subscription.id,
                    status: subscription.status,
                    cancelAtPeriodEnd: subscription.cancel_at_period_end,
                },
            });
        } catch (err: any) {
            console.error("Subscription cancellation error:", err);
            res.status(500).json({
                message: "Failed to cancel subscription",
                error: err.message
            });
        }
    });

    // Reactivate subscription
    app.post("/api/billing/reactivate-subscription", isAuthenticatedToken, async (req: Request, res: Response): Promise<any> => {
        try {
            const userId = req.user?.userId;
            const user = await storage.getUser(userId);

            if (!user?.stripeSubscriptionId) {
                return res.status(404).json({ message: "No active subscription found" });
            }

            const subscription = await stripe.subscriptions.update(user.stripeSubscriptionId, {
                cancel_at_period_end: false,
            });

            await storage.updateUserSubscriptionStatus(userId, subscription.status);

            res.json({
                message: "Subscription reactivated successfully",
                subscription: {
                    id: subscription.id,
                    status: subscription.status,
                    cancelAtPeriodEnd: subscription.cancel_at_period_end,
                },
            });
        } catch (err: any) {
            console.error("Subscription reactivation error:", err);
            res.status(500).json({
                message: "Failed to reactivate subscription",
                error: err.message
            });
        }
    });

    // Get invoices
    app.get("/api/billing/invoices", isAuthenticatedToken, async (req: Request, res: Response): Promise<any> => {
        try {
            const userId = req.user?.userId;
            const user = await storage.getUser(userId);

            if (!user?.stripeCustomerId) {
                return res.status(404).json({ message: "No billing account found" });
            }

            const invoices = await stripe.invoices.list({
                customer: user.stripeCustomerId,
                limit: 10,
            });

            res.json({
                invoices: invoices.data.map(invoice => ({
                    id: invoice.id,
                    amount_paid: invoice.amount_paid,
                    currency: invoice.currency,
                    status: invoice.status,
                    created: invoice.created,
                    period_start: invoice.period_start,
                    period_end: invoice.period_end,
                    invoice_pdf: invoice.invoice_pdf,
                })),
            });
        } catch (err: any) {
            console.error("Invoice retrieval error:", err);
            res.status(500).json({
                message: "Failed to retrieve invoices",
                error: err.message
            });
        }
    });

    // Create customer
    app.post("/api/billing/customer", isAuthenticatedToken, async (req: Request, res: Response): Promise<any> => {
        try {
            const userId = req.user?.userId;
            const { email, name } = req.body;

            const user = await storage.getUser(userId);
            if (user?.stripeCustomerId) {
                return res.status(400).json({ message: "Customer already exists" });
            }

            const customer = await stripe.customers.create({
                email,
                name,
                metadata: {
                    userId: userId,
                },
            });

            await storage.updateUserStripeCustomerId(userId, customer.id);

            res.json({
                message: "Customer created successfully",
                customer: {
                    id: customer.id,
                    email: customer.email,
                    name: customer.name,
                },
            });
        } catch (err: any) {
            console.error("Customer creation error:", err);
            res.status(500).json({
                message: "Failed to create customer",
                error: err.message
            });
        }
    });

    // Add payment method
    app.post("/api/billing/payment-method", isAuthenticatedToken, async (req: Request, res: Response): Promise<any> => {
        try {
            const userId = req.user?.userId;
            const { paymentMethodId } = req.body;

            const user = await storage.getUser(userId);
            if (!user?.stripeCustomerId) {
                return res.status(404).json({ message: "No billing account found" });
            }

            await stripe.paymentMethods.attach(paymentMethodId, {
                customer: user.stripeCustomerId,
            });

            await stripe.customers.update(user.stripeCustomerId, {
                invoice_settings: {
                    default_payment_method: paymentMethodId,
                },
            });

            res.json({ message: "Payment method added successfully" });
        } catch (err: any) {
            console.error("Payment method addition error:", err);
            res.status(500).json({
                message: "Failed to add payment method",
                error: err.message
            });
        }
    });

    // Get payment methods
    app.get("/api/billing/payment-methods", isAuthenticatedToken, async (req: Request, res: Response): Promise<any> => {
        try {
            const userId = req.user?.userId;
            const user = await storage.getUser(userId);

            if (!user?.stripeCustomerId) {
                return res.status(404).json({ message: "No billing account found" });
            }

            const paymentMethods = await stripe.paymentMethods.list({
                customer: user.stripeCustomerId,
                type: 'card',
            });

            res.json({
                paymentMethods: paymentMethods.data.map(pm => ({
                    id: pm.id,
                    type: pm.type,
                    card: pm.card ? {
                        brand: pm.card.brand,
                        last4: pm.card.last4,
                        exp_month: pm.card.exp_month,
                        exp_year: pm.card.exp_year,
                    } : null,
                })),
            });
        } catch (err: any) {
            console.error("Payment method retrieval error:", err);
            res.status(500).json({
                message: "Failed to retrieve payment methods",
                error: err.message
            });
        }
    });

    // Webhook handler for Stripe events
    app.post("/api/billing/webhook", express.raw({ type: 'application/json' }), async (req: Request, res: Response): Promise<any> => {
        console.log('🔔 Webhook received - Headers:', Object.keys(req.headers));
        console.log('🔔 Webhook received - Body length:', req.body?.length);
        console.log('🔔 Webhook received - Content-Type:', req.headers['content-type']);
        
        const sig = req.headers['stripe-signature'];
        const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

        console.log('Webhook secret configured:', !!endpointSecret);
        console.log('Webhook secret starts with:', endpointSecret?.substring(0, 10) + '...');
        console.log('🔔 Stripe signature present:', !!sig);
        console.log('🔔 Stripe signature starts with:', (sig as string)?.substring(0, 10) + '...');

        if (!endpointSecret) {
            console.error('STRIPE_WEBHOOK_SECRET is not configured');
            res.status(500).json({ error: 'Webhook secret not configured' });
            return;
        }

        if (!sig) {
            console.error('No Stripe signature found in headers');
            res.status(400).json({ error: 'No signature found' });
            return;
        }

        let event: Stripe.Event;

        try {
            event = stripe.webhooks.constructEvent(req.body, sig as string, endpointSecret);
            console.log('Webhook signature verification successful');
        } catch (err: any) {
            console.error('Webhook signature verification failed:', err.message);
            console.error('Signature:', sig);
            console.error('Body length:', req.body?.length);
            console.error('Body preview:', req.body?.toString().substring(0, 200));
            res.status(400).send(`Webhook Error: ${err.message}`);
            return;
        }

        try {
            console.log('🔔 Webhook received:', event.type, 'for event ID:', event.id);
            
            switch (event.type) {
                case 'checkout.session.completed':
                    const session = event.data.object as Stripe.Checkout.Session;
                    console.log('✅ Checkout session completed:', session.id);
                    console.log('📝 Session metadata:', session.metadata);
                    console.log('📝 Session subscription:', session.subscription);
                    console.log('👤 Session customer:', session.customer);

                    if (session.subscription && session.customer) {
                        const userId = session.metadata?.userId;
                        console.log('🔍 Looking for userId in metadata:', userId);
                        
                        if (userId) {
                            console.log('✅ Found userId, updating database for user:', userId);
                            try {
                                await storage.updateUserStripeCustomerId(userId, session.customer as string);
                                await storage.updateUserStripeSubscriptionId(userId, session.subscription as string);
                                await storage.updateUserSubscriptionStatus(userId, 'active');
                                console.log('✅ Database updated successfully for user:', userId);
                            } catch (dbError) {
                                console.error('❌ Database update failed for user:', userId, 'Error:', dbError);
                            }
                        } else {
                            console.log('❌ No userId found in session metadata');
                        }
                    } else {
                        console.log('❌ Session missing subscription or customer');
                        console.log('   Subscription:', session.subscription);
                        console.log('   Customer:', session.customer);
                    }
                    break;

                case 'customer.subscription.updated':
                    const subscription = event.data.object as Stripe.Subscription;
                    console.log('📝 Subscription updated:', subscription.id);
                    console.log('📝 Subscription metadata:', subscription.metadata);

                    const subUserId = subscription.metadata?.userId;
                    if (subUserId) {
                        console.log('✅ Updating subscription status for user:', subUserId, 'to:', subscription.status);
                        try {
                            await storage.updateUserSubscriptionStatus(subUserId, subscription.status);
                        } catch (dbError) {
                            console.error('❌ Database update failed for user:', subUserId, 'Error:', dbError);
                        }
                    } else {
                        console.log('❌ No userId found in subscription metadata');
                    }
                    break;

                case 'customer.subscription.deleted':
                    const deletedSubscription = event.data.object as Stripe.Subscription;
                    console.log('🗑️ Subscription deleted:', deletedSubscription.id);
                    console.log('📝 Deleted subscription metadata:', deletedSubscription.metadata);

                    const deletedUserId = deletedSubscription.metadata?.userId;
                    if (deletedUserId) {
                        console.log('✅ Updating subscription status for user:', deletedUserId, 'to: canceled');
                        try {
                            await storage.updateUserSubscriptionStatus(deletedUserId, 'canceled');
                        } catch (dbError) {
                            console.error('❌ Database update failed for user:', deletedUserId, 'Error:', dbError);
                        }
                    } else {
                        console.log('❌ No userId found in deleted subscription metadata');
                    }
                    break;

                case 'invoice.payment_succeeded':
                    const invoice = event.data.object as Stripe.Invoice;
                    console.log('💰 Invoice payment succeeded:', invoice.id);
                    console.log('📝 Invoice metadata:', invoice.metadata);
                    break;

                case 'invoice.payment_failed':
                    const failedInvoice = event.data.object as Stripe.Invoice;
                    console.log('❌ Invoice payment failed:', failedInvoice.id);
                    console.log('📝 Failed invoice metadata:', failedInvoice.metadata);

                    const failedUserId = failedInvoice.metadata?.userId;
                    if (failedUserId) {
                        console.log('✅ Updating subscription status for user:', failedUserId, 'to: past_due');
                        try {
                            await storage.updateUserSubscriptionStatus(failedUserId, 'past_due');
                        } catch (dbError) {
                            console.error('❌ Database update failed for user:', failedUserId, 'Error:', dbError);
                        }
                    } else {
                        console.log('❌ No userId found in failed invoice metadata');
                    }
                    break;

                default:
                    console.log(`ℹ️ Unhandled event type: ${event.type}`);
            }

            res.json({ received: true });
        } catch (err: any) {
            console.error('❌ Webhook handler error:', err);
            res.status(500).json({ error: 'Webhook handler failed' });
        }
    });

    // Manual webhook test endpoint for individual subscriptions (development/testing)
    app.post("/api/billing/test-subscription-webhook", async (req, res) => {
        try {
            const { sessionId, userId } = req.body;

            if (!sessionId || !userId) {
                res.status(400).json({ message: "Session ID and User ID are required" });
                return;
            }

            console.log('🧪 Manual subscription webhook test for session:', sessionId, 'user:', userId);

            // Retrieve the checkout session from Stripe
            const session = await stripe.checkout.sessions.retrieve(sessionId);
            console.log('✅ Retrieved session:', session.id, 'status:', session.status);
            console.log('📝 Session metadata:', session.metadata);
            console.log('📝 Session subscription:', session.subscription);
            console.log('👤 Session customer:', session.customer);

            if (session.subscription && session.customer) {
                console.log('✅ Session has subscription and customer');
                console.log('📝 Subscription ID:', session.subscription);
                console.log('👤 Customer ID:', session.customer);

                // Check if the session metadata has the correct userId
                if (session.metadata?.userId && session.metadata.userId === userId) {
                    console.log('✅ Session metadata matches provided userId');
                } else {
                    console.log('⚠️ Session metadata userId mismatch or missing');
                    console.log('   Expected:', userId);
                    console.log('   Found:', session.metadata?.userId);
                    console.log('   This might cause issues with automatic webhook processing');
                }

                // Update the user's database record
                try {
                    await storage.updateUserStripeCustomerId(userId, session.customer as string);
                    await storage.updateUserStripeSubscriptionId(userId, session.subscription as string);
                    await storage.updateUserSubscriptionStatus(userId, 'active');

                    console.log('✅ Database updated successfully');

                    res.json({ 
                        message: "Subscription webhook processed manually",
                        sessionId: session.id,
                        subscriptionId: session.subscription,
                        customerId: session.customer,
                        userId: userId,
                        status: 'active',
                        metadataMatch: session.metadata?.userId === userId
                    });
                } catch (dbError) {
                    console.error('❌ Database update failed:', dbError);
                    res.status(500).json({ 
                        message: "Database update failed",
                        error: dbError instanceof Error ? dbError.message : 'Unknown error'
                    });
                }
            } else {
                console.log('❌ Session missing subscription or customer');
                res.status(400).json({ 
                    message: "Session does not have subscription or customer",
                    session: {
                        id: session.id,
                        status: session.status,
                        subscription: session.subscription,
                        customer: session.customer,
                        metadata: session.metadata
                    }
                });
            }
        } catch (error) {
            console.error("❌ Error in manual subscription webhook test:", error);
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            res.status(500).json({ message: "Failed to process subscription webhook", error: errorMessage });
        }
    });

    // Test endpoint to check webhook secret configuration
    app.get("/api/billing/test-webhook-secret", async (req, res) => {
        const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
        res.json({
            secretConfigured: !!endpointSecret,
            secretStartsWith: endpointSecret?.substring(0, 10) + '...',
            secretLength: endpointSecret?.length,
            expectedSecret: 'whsec_8cce5511dacfe3c5e98b9e65c2c0bae8def59f5ce8b4589347e67f548b65e0fd'
        });
    });

    // Manual activation endpoint for direct subscription activation
    app.post("/api/billing/manual-activate", async (req, res) => {
        try {
            const { sessionId, userId } = req.body;

            if (!sessionId || !userId) {
                res.status(400).json({ message: "Session ID and User ID are required" });
                return;
            }

            console.log('🔧 Manual activation for session:', sessionId, 'user:', userId);

            // Retrieve the checkout session from Stripe
            const session = await stripe.checkout.sessions.retrieve(sessionId);
            console.log('✅ Retrieved session:', session.id, 'status:', session.status);

            if (session.status === 'complete' && session.subscription && session.customer) {
                console.log('✅ Session is complete with subscription and customer');

                // Update the user's database record
                try {
                    await storage.updateUserStripeCustomerId(userId, session.customer as string);
                    await storage.updateUserStripeSubscriptionId(userId, session.subscription as string);
                    await storage.updateUserSubscriptionStatus(userId, 'active');

                    console.log('✅ Database updated successfully for manual activation');

                    res.json({ 
                        message: "Subscription activated manually",
                        sessionId: session.id,
                        subscriptionId: session.subscription,
                        customerId: session.customer,
                        userId: userId,
                        status: 'active'
                    });
                } catch (dbError) {
                    console.error('❌ Database update failed during manual activation:', dbError);
                    res.status(500).json({ 
                        message: "Database update failed",
                        error: dbError instanceof Error ? dbError.message : 'Unknown error'
                    });
                }
            } else {
                console.log('❌ Session not complete or missing subscription/customer');
                res.status(400).json({ 
                    message: "Session is not complete or missing subscription/customer",
                    session: {
                        id: session.id,
                        status: session.status,
                        subscription: session.subscription,
                        customer: session.customer
                    }
                });
            }
        } catch (error) {
            console.error("❌ Error in manual activation:", error);
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            res.status(500).json({ message: "Failed to activate subscription", error: errorMessage });
        }
    });

    // Validate coupon
    app.post("/api/billing/validate-coupon", async (req: Request, res: Response): Promise<any> => {
        const { code } = req.body;

        try {
            const coupons = await stripe.coupons.list({ limit: 100 }); // or use `promotionCodes.list` if you're using promo codes
            const promo = await stripe.promotionCodes.list({
                code,
                active: true,
            });

            if (!promo.data.length) {
                return res.status(400).json({ valid: false, message: "Invalid or expired promo code." });
            }

            const promoCode = promo.data[0];

            return res.json({
                valid: true,
                discount: promoCode.coupon.percent_off || promoCode.coupon.amount_off,
                type: promoCode.coupon.percent_off ? "percent" : "amount",
                message: "Access Granted!",
            });
        } catch (error) {
            console.error("Coupon validation failed:", error);
            return res.status(500).json({ valid: false, message: "Something went wrong." });
        }
    });



    // ==================== Facility Management ====================== //

    // Get facility information
    app.get("/api/facility", isAuthenticatedToken, async (req, res) => {
        try {
            const userId = req.user?.userId as string | undefined;
            if (!userId) {
                res.status(401).json({ message: "Unauthorized" });
                return;
            }

            // Load the user and their facility
            const [user] = await db.select().from(users).where(eq(users.id, userId));

            let facility;
            if (user?.facilityId) {
                const [existingFacility] = await db.select().from(facilities).where(eq(facilities.id, user.facilityId));
                facility = existingFacility;
            }

            // If no facility assigned or not found, create a default basic facility and link to user
            if (!facility) {
                console.log("No facility found for user, creating default basic facility and linking to user");
                facility = await storage.createFacility({
                    name: "",
                    address: "",
                    phone: "",
                    adminEmail: user?.email || "",
                    tagline: "",
                    logoUrl: "",
                    brandColor: "#3B82F6",
                    monthlyPrice: "",
                    promoCode: "",
                    subscriptionTier: "basic"
                });

                await db.update(users)
                    .set({ facilityId: facility.id, updatedAt: new Date() })
                    .where(eq(users.id, userId));
            }

            res.json(facility || {});
        } catch (error) {
            console.error("Error fetching facility:", error);
            res.status(500).json({ message: "Failed to fetch facility" });
        }
    });

    // Create or update facility for current user
    app.post("/api/facility", isAuthenticatedToken, async (req, res) => {
        try {
            const userId = req.user?.userId as string | undefined;
            if (!userId) {
                res.status(401).json({ message: "Unauthorized" });
                return;
            }

            const { name, address, phone, email, tagline, logoUrl, brandColor, monthlyPrice, promoCode, subscriptionTier } = req.body;

            console.log("Facility upsert request:", { name, address, phone, email, tagline, logoUrl, brandColor, monthlyPrice, promoCode, subscriptionTier });

            // Get current user to check if facility exists
            const [user] = await db.select().from(users).where(eq(users.id, userId));

            let facility;
            if (user?.facilityId) {
                // Update existing facility
                facility = await storage.updateFacility({
                    id: user.facilityId,
                    name: name ?? "",
                    address: address ?? "",
                    phone: phone ?? "",
                    adminEmail: email ?? (user?.email as string | undefined) ?? "",
                    tagline: tagline ?? "",
                    logoUrl: logoUrl ?? "",
                    brandColor: brandColor ?? "#3B82F6",
                    monthlyPrice: monthlyPrice ?? undefined,
                    promoCode: promoCode ?? undefined,
                });
                console.log("Facility updated successfully:", facility);
                res.json(facility);
            } else {
                // Create new basic facility and link to user
                facility = await storage.createFacility({
                    name: name || "",
                    address: address || "",
                    phone: phone || "",
                    adminEmail: email || user?.email || "",
                    tagline: tagline || "",
                    logoUrl: logoUrl || "",
                    brandColor: brandColor || "#3B82F6",
                    monthlyPrice: monthlyPrice || "",
                    promoCode: promoCode || "",
                    subscriptionTier: subscriptionTier || "basic"
                });

                await db.update(users)
                    .set({ facilityId: facility.id, updatedAt: new Date() })
                    .where(eq(users.id, userId));

                console.log("Facility created and linked to user:", facility);
                res.status(201).json(facility);
            }
        } catch (error) {
            console.error("Error creating facility:", error);
            res.status(500).json({ message: "Failed to create facility" });
        }
    });

    // Update an existing facility
    app.put("/api/facility/:id", async (req, res) => {
        try {
            const { id } = req.params;
            const { name, address, phone, email, tagline, logoUrl, brandColor } = req.body;

            console.log("Facility update request:", { id, name, address, phone, email, tagline, logoUrl, brandColor });

            const facility = await storage.updateFacility({
                id,
                name,
                address,
                phone,
                adminEmail: email,
                tagline,
                logoUrl,
                brandColor
            });

            console.log("Facility updated successfully:", facility);
            res.json(facility);
        } catch (error) {
            console.error("Error updating facility:", error);
            res.status(500).json({ message: "Failed to update facility" });
        }
    });


    // Logo upload endpoint
    app.post("/api/facility/logo", upload.single("logo"), async (req, res) => {
        try {
            if (!req.file) {
                res.status(400).json({ message: "No file uploaded" });
                return;
            }

            // Get the user ID from the request (you might need to add authentication here)
            const userId = req.body.userId || req.headers['x-user-id'];
            
            if (!userId) {
                res.status(400).json({ message: "User ID is required" });
                return;
            }

            // Get the user's facility
            const [user] = await db.select().from(users).where(eq(users.id, userId));
            if (!user?.facilityId) {
                res.status(404).json({ message: "User not linked to facility" });
                return;
            }

            // Return the URL to the uploaded file
            const logoUrl = `/uploads/${req.file.filename}`;
            
            // Update the facility with the new logo URL
            const updatedFacility = await storage.updateFacility({
                id: user.facilityId,
                logoUrl: logoUrl
            });

            console.log('Logo uploaded and facility updated:', { logoUrl, facilityId: user.facilityId });

            res.json({ 
                logoUrl,
                facility: updatedFacility,
                message: "Logo uploaded and facility updated successfully"
            });
        } catch (error) {
            console.error("Error uploading logo:", error);
            res.status(500).json({ message: "Failed to upload logo" });
        }
    });

    // Get facility billing settings
    app.get("/api/facility/billing", isAuthenticatedToken, async (req, res) => {
        try {
            const userId = req.user?.userId as string | undefined;
            if (!userId) {
                res.status(401).json({ message: "Unauthorized" });
                return;
            }

            const [user] = await db.select().from(users).where(eq(users.id, userId));
            let facility;
            if (user?.facilityId) {
                const [existingFacility] = await db.select().from(facilities).where(eq(facilities.id, user.facilityId));
                facility = existingFacility;
            }

            // Use the stored monthly price or fallback to tier-based calculation
            let monthlyPrice = facility?.monthlyPrice || "25"; // default
            if (!facility?.monthlyPrice) {
                // Fallback to tier-based calculation if no price is stored
                if (facility?.subscriptionTier === "basic") {
                    monthlyPrice = "15";
                } else if (facility?.subscriptionTier === "premium") {
                    monthlyPrice = "25";
                }
            }

            res.json({
                monthlyPrice: monthlyPrice,
                promoCode: facility?.promoCode || "",
                stripePriceId: facility?.stripePriceId || "",
                stripeCouponId: facility?.stripeCouponId || "",
            });
        } catch (error) {
            console.error("Error fetching facility billing:", error);
            res.status(500).json({ message: "Failed to fetch billing settings" });
        }
    });

    // Update facility billing settings
    app.post("/api/facility/billing", isAuthenticatedToken, async (req, res) => {
        try {
            const { monthlyPrice, promoCode } = req.body;

            // Validate inputs
            if (!monthlyPrice || isNaN(Number(monthlyPrice))) {
                res.status(400).json({ message: "Invalid monthly price" });
                return;
            }

            const userId = req.user?.userId as string | undefined;
            if (!userId) {
                res.status(401).json({ message: "Unauthorized" });
                return;
            }

            const [user] = await db.select().from(users).where(eq(users.id, userId));
            let facility;
            if (user?.facilityId) {
                const [existingFacility] = await db.select().from(facilities).where(eq(facilities.id, user.facilityId));
                facility = existingFacility;
            }

            if (!facility) {
                res.status(404).json({ message: "Facility not found" });
                return;
            }

            // Create or update Stripe product and price (skip in dev if key missing)
            let stripeProductId = facility.stripeProductId;
            let stripePriceId = facility.stripePriceId;

            const stripeEnabled = !!process.env.STRIPE_SECRET_KEY;
            if (stripeEnabled) {
                if (!stripeProductId) {
                    const product = await stripe.products.create({
                        name: `${facility.name} Subscription`,
                        description: `Monthly subscription for ${facility.name}`,
                        metadata: {
                            facilityId: facility.id,
                        },
                    });
                    stripeProductId = product.id;
                }

                const price = await stripe.prices.create({
                    product: stripeProductId,
                    unit_amount: Number(monthlyPrice) * 100,
                    currency: 'usd',
                    recurring: { interval: 'month' },
                    metadata: { facilityId: facility.id },
                });
                stripePriceId = price.id;
            }

            // Create or update Stripe coupon if promo code provided
            let stripeCouponId = null;
            if (promoCode && promoCode.trim() && stripeEnabled) {
                try {
                    const existingCoupons = await stripe.coupons.list({ limit: 100 });
                    const existingCoupon = existingCoupons.data.find(c => c.name === promoCode);
                    if (existingCoupon) {
                        stripeCouponId = existingCoupon.id;
                    } else {
                        const coupon = await stripe.coupons.create({
                            name: promoCode,
                            percent_off: 100,
                            duration: 'forever',
                            metadata: { facilityId: facility.id },
                        });
                        stripeCouponId = coupon.id;
                    }
                } catch (error) {
                    console.error("Error creating Stripe coupon:", error);
                }
            }

            // Update facility with new billing settings and Stripe IDs
            const updatedFacility = await storage.updateFacility({
                ...facility,
                subscriptionTier: Number(monthlyPrice) >= 25 ? "premium" : "basic",
                monthlyPrice: monthlyPrice, // Store the actual price
                promoCode: promoCode || null,
                stripeProductId: stripeProductId,
                stripePriceId: stripePriceId,
                stripeCouponId: stripeCouponId,
            });

            res.json({
                message: "Billing settings updated successfully",
                facility: updatedFacility,
                stripePriceId: stripePriceId,
            });
        } catch (error) {
            console.error("Error updating facility billing:", error);
            res.status(500).json({ message: "Failed to update billing settings" });
        }
    });

    // ==================== Flat Payment Invite System ====================== //

    // Get available invite packages for a facility
    app.get("/api/facility/invite-packages", isAuthenticatedToken, async (req, res) => {
        try {
            const userId = req.user?.userId as string | undefined;
            if (!userId) {
                return res.status(400).json({ message: "Unauthorized" });
            }

            // Get user's facility
            const [user] = await db.select().from(users).where(eq(users.id, userId));
            if (!user?.facilityId) {
                return res.status(404).json({ message: "User not linked to facility" });
            }

            // Get or create default packages for this facility
            const packages = await storage.getFacilityInvitePackages(user.facilityId);
            if (packages.length === 0) {
                const defaultPackages = [
                    { inviteCount: 10, priceInCents: 10000, packageName: "10 Invites Package" },
                    { inviteCount: 25, priceInCents: 22500, packageName: "25 Invites Package" },
                    { inviteCount: 50, priceInCents: 40000, packageName: "50 Invites Package" },
                ];
                for (const pkg of defaultPackages) {
                    await storage.createFacilityInvitePackage({
                        facilityId: user.facilityId,
                        ...pkg,
                        isActive: true
                    });
                }
                const createdPackages = await storage.getFacilityInvitePackages(user.facilityId);
                res.json(createdPackages);
            } else {
                res.json(packages);
            }
        } catch (error) {
            console.error("Error fetching invite packages:", error);
            res.status(500).json({ message: "Failed to fetch invite packages" });
        }
    });

    // Create Stripe checkout session for invite package purchase (with dev bypass)
    app.post("/api/facility/purchase-invites", isAuthenticatedToken, async (req, res) => {
        try {
            const { packageId } = req.body;

            if (!packageId) {
                res.status(400).json({ message: "Package ID is required" });
                return;
            }

            const userId = req.user?.userId as string | undefined;
            if (!userId) {
                res.status(401).json({ message: "Unauthorized" });
                return;
            }

            const [user] = await db.select().from(users).where(eq(users.id, userId));
            let facility;
            if (user?.facilityId) {
                const [existingFacility] = await db.select().from(facilities).where(eq(facilities.id, user.facilityId));
                facility = existingFacility;
            }

            if (!facility) {
                res.status(404).json({ message: "Facility not found" });
                return;
            }

            // Get the package details
            const packageDetails = await storage.getFacilityInvitePackage(packageId);
            if (!packageDetails) {
                res.status(404).json({ message: "Package not found" });
                return;
            }

            const stripeEnabled = !!process.env.STRIPE_SECRET_KEY;

            if (!stripeEnabled) {
                res.status(500).json({ message: "Stripe is not configured" });
                return;
            }

            // const appUrl = process.env.APP_URL || process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';
            // Create Stripe checkout session
            const sessionParams: Stripe.Checkout.SessionCreateParams = {
                payment_method_types: ['card'],
                line_items: [{
                    price_data: {
                        currency: 'usd',
                        product_data: {
                            name: packageDetails.packageName,
                            description: `${packageDetails.inviteCount} invites for ${facility.name}`,
                        },
                        unit_amount: packageDetails.priceInCents,
                    },
                    quantity: 1,
                }],
                mode: 'payment',
                success_url: `${process.env.NEXT_PUBLIC_APP_URL}/dashboard/settings?success=true&package_id=${packageId}`,
                cancel_url: `${process.env.NEXT_PUBLIC_APP_URL}/dashboard/settings?canceled=true`,
                metadata: {
                    facilityId: facility.id,
                    packageId: packageId.toString(),
                    inviteCount: packageDetails.inviteCount.toString(),
                    priceInCents: packageDetails.priceInCents.toString(),
                },
            };

            console.log('Creating Stripe checkout session with params:', JSON.stringify(sessionParams, null, 2));

            const session = await stripe.checkout.sessions.create(sessionParams);
            console.log('Stripe session created:', session.id);

            // Create purchase record
            const purchase = await storage.createFacilityInvitePurchase({
                facilityId: facility.id,
                packageId: packageId,
                stripeSessionId: session.id,
                totalPaidInCents: packageDetails.priceInCents,
                inviteCount: packageDetails.inviteCount,
                status: 'pending'
            });

            console.log('Purchase record created:', purchase.id);

            res.json({ sessionId: session.id, url: session.url });
        } catch (error) {
            console.error("Error creating checkout session:", error);
            res.status(500).json({ message: "Failed to create checkout session" });
        }
    });

    // Get facility's invite purchases
    app.get("/api/facility/invite-purchases", isAuthenticatedToken, async (req, res) => {
        try {
            const userId = req.user?.userId as string | undefined;
            if (!userId) {
                return res.status(400).json({ message: "Unauthorized" });
            }
            const [user] = await db.select().from(users).where(eq(users.id, userId));
            if (!user?.facilityId) {
                return res.status(404).json({ message: "User not linked to facility" });
            }
            const purchases = await storage.getFacilityInvitePurchases(user.facilityId);
            res.json(purchases);
        } catch (error) {
            console.error("Error fetching invite purchases:", error);
            res.status(500).json({ message: "Failed to fetch invite purchases" });
        }
    });

    // Get facility's available invites
    app.get("/api/facility/available-invites", isAuthenticatedToken, async (req, res) => {
        try {
            const userId = req.user?.userId as string | undefined;
            if (!userId) {
                return res.status(400).json({ message: "Unauthorized" });
            }
            const [user] = await db.select().from(users).where(eq(users.id, userId));
            if (!user?.facilityId) {
                return res.status(404).json({ message: "User not linked to facility" });
            }
            const invites = await storage.getFacilityAvailableInvites(user.facilityId);
            res.json(invites);
        } catch (error) {
            console.error("Error fetching available invites:", error);
            res.status(500).json({ message: "Failed to fetch available invites" });
        }
    });

    // Create invite codes for a purchase
    app.post("/api/facility/create-invites", isAuthenticatedToken, async (req, res) => {
        try {
            const { purchaseId, inviteCount } = req.body;

            if (!purchaseId || !inviteCount) {
                res.status(400).json({ message: "Purchase ID and invite count are required" });
                return;
            }

            const userId = req.user?.userId as string | undefined;
            if (!userId) {
                return res.status(400).json({ message: "Unauthorized" });
            }

            const [user] = await db.select().from(users).where(eq(users.id, userId));
            if (!user?.facilityId) {
                return res.status(404).json({ message: "User not linked to facility" });
            }

            // Check invite limits before creating new invites
            const purchases = await db
                .select()
                .from(facilityInvitePurchases)
                .where(eq(facilityInvitePurchases.facilityId, user.facilityId));
            
            let totalPurchased = 0;
            purchases.forEach(purchase => {
                if (purchase.inviteCount && purchase.status === 'completed') {
                    totalPurchased += purchase.inviteCount;
                }
            });

            const allInvites = await db
                .select()
                .from(facilityInvites)
                .where(eq(facilityInvites.facilityId, user.facilityId));
            
            const usedInvites = allInvites.filter(invite => invite.status === 'used').length;
            
            if (usedInvites >= totalPurchased && totalPurchased > 0) {
                return res.status(403).json({ 
                    message: "Invitation limit reached. You have used all your purchased invites.",
                    limitReached: true,
                    totalPurchased,
                    usedInvites
                });
            }

            // Generate invite codes
            const invites = await storage.createFacilityInvites(user.facilityId, purchaseId, inviteCount);

            res.json({
                message: "Invites created successfully",
                invites: invites,
                count: invites.length
            });
        } catch (error) {
            console.error("Error creating invites:", error);
            res.status(500).json({ message: "Failed to create invites" });
        }
    });

    // Manual webhook test endpoint (for development)
    app.post("/api/facility/test-webhook", async (req, res) => {
        try {
            const { sessionId } = req.body;

            if (!sessionId) {
                res.status(400).json({ message: "Session ID is required" });
                return;
            }

            console.log('🧪 Manual webhook test for session:', sessionId);

            // Find the purchase by session ID
            const [purchase] = await db
                .select()
                .from(facilityInvitePurchases)
                .where(eq(facilityInvitePurchases.stripeSessionId, sessionId));

            if (!purchase) {
                console.error('❌ Purchase not found for session:', sessionId);
                return res.status(404).json({ message: "Purchase not found for this session ID" });
            }

            console.log('✅ Found purchase:', purchase.id, 'for facility:', purchase.facilityId);

            // Update the purchase status to completed manually
            await db.update(facilityInvitePurchases)
                .set({
                    status: 'completed',
                    completedAt: new Date()
                })
                .where(eq(facilityInvitePurchases.stripeSessionId, sessionId));

            console.log('✅ Purchase marked as completed');

            // Check if invites already exist
            const existingInvites = await db
                .select()
                .from(facilityInvites)
                .where(eq(facilityInvites.purchaseId, purchase.id));

            console.log('📋 Existing invites count:', existingInvites.length);

            if (!existingInvites || existingInvites.length === 0) {
                console.log('🧾 Creating invites for purchase:', purchase.id);
                console.log('🎫 Invite count to create:', purchase.inviteCount);
                console.log('🏥 Facility ID for invites:', purchase.facilityId);
                
                const createdInvites = await storage.createFacilityInvites(
                    purchase.facilityId, 
                    purchase.id, 
                    purchase.inviteCount
                );
                
                console.log('✅ Invites created successfully:', createdInvites.length);
                console.log('🎫 First few invite codes:', createdInvites.slice(0, 3).map(invite => invite.inviteCode));
                
                res.json({ 
                    message: "Purchase status updated to completed and invites created",
                    purchaseId: purchase.id,
                    invitesCreated: createdInvites.length,
                    sampleInviteCodes: createdInvites.slice(0, 3).map(invite => invite.inviteCode)
                });
            } else {
                console.log('ℹ️ Invites already exist for purchase:', purchase.id);
                console.log('🎫 Existing invite codes:', existingInvites.slice(0, 3).map(invite => invite.inviteCode));
                
                res.json({ 
                    message: "Purchase status updated to completed, invites already exist",
                    purchaseId: purchase.id,
                    existingInvites: existingInvites.length,
                    sampleInviteCodes: existingInvites.slice(0, 3).map(invite => invite.inviteCode)
                });
            }
        } catch (error) {
            console.error("Error in manual webhook test:", error);
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            res.status(500).json({ message: "Failed to update purchase status", error: errorMessage });
        }
    });

    // Check invite purchase status and available invites
    app.get("/api/facility/invite-status", isAuthenticatedToken, async (req, res) => {
        try {
            const userId = req.user?.userId as string | undefined;
            if (!userId) {
                return res.status(401).json({ message: "Unauthorized" });
            }

            const [user] = await db.select().from(users).where(eq(users.id, userId));
            if (!user?.facilityId) {
                return res.status(404).json({ message: "User not linked to facility" });
            }

            // Get all purchases for this facility
            const purchases = await db
                .select()
                .from(facilityInvitePurchases)
                .where(eq(facilityInvitePurchases.facilityId, user.facilityId));

            // Get all available invites for this facility
            const availableInvites = await db
                .select()
                .from(facilityInvites)
                .where(eq(facilityInvites.facilityId, user.facilityId));

            // Get all invite packages
            const packages = await db
                .select()
                .from(facilityInvitePackages)
                .where(eq(facilityInvitePackages.facilityId, user.facilityId));

            res.json({
                facilityId: user.facilityId,
                purchases: purchases.map(p => ({
                    id: p.id,
                    packageId: p.packageId,
                    stripeSessionId: p.stripeSessionId,
                    status: p.status,
                    inviteCount: p.inviteCount,
                    totalPaidInCents: p.totalPaidInCents,
                    purchasedAt: p.purchasedAt,
                    completedAt: p.completedAt
                })),
                availableInvites: availableInvites.map(i => ({
                    id: i.id,
                    inviteCode: i.inviteCode,
                    purchaseId: i.purchaseId,
                    status: i.status,
                    usedByUserId: i.usedByUserId,
                    usedAt: i.usedAt,
                    createdAt: i.createdAt
                })),
                packages: packages.map(p => ({
                    id: p.id,
                    packageName: p.packageName,
                    inviteCount: p.inviteCount,
                    priceInCents: p.priceInCents,
                    isActive: p.isActive
                })),
                summary: {
                    totalPurchases: purchases.length,
                    completedPurchases: purchases.filter(p => p.status === 'completed').length,
                    pendingPurchases: purchases.filter(p => p.status === 'pending').length,
                    totalInvites: availableInvites.length,
                    usedInvites: availableInvites.filter(i => i.status === 'used').length,
                    availableInvites: availableInvites.filter(i => i.status === 'unused').length
                }
            });
        } catch (error) {
            console.error("Error checking invite status:", error);
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            res.status(500).json({ message: "Failed to check invite status", error: errorMessage });
        }
    });

    // Check user's invite limits and available invites for restricting patient invitations
    app.get("/api/facility/invite-limits", isAuthenticatedToken, async (req, res) => {
        try {
            const userId = req.user?.userId as string | undefined;
            if (!userId) {
                return res.status(401).json({ message: "Unauthorized" });
            }

            const [user] = await db.select().from(users).where(eq(users.id, userId));
            if (!user?.facilityId) {
                return res.status(404).json({ message: "User not linked to facility" });
            }

            // Get all invite purchases for this facility
            const purchases = await db
                .select()
                .from(facilityInvitePurchases)
                .where(eq(facilityInvitePurchases.facilityId, user.facilityId));
            
            // Calculate total purchased invites
            let totalPurchased = 0;
            purchases.forEach(purchase => {
                if (purchase.inviteCount && purchase.status === 'completed') {
                    totalPurchased += purchase.inviteCount;
                }
            });

            // Get all invites for this facility
            const allInvites = await db
                .select()
                .from(facilityInvites)
                .where(eq(facilityInvites.facilityId, user.facilityId));
            
            // Count used invites
            const usedInvites = allInvites.filter(invite => invite.status === 'used').length;
            
            // Count available invites
            const availableInvites = allInvites.filter(invite => invite.status === 'unused').length;

            res.json({
                totalPurchased,
                usedInvites,
                availableInvites,
                canInvite: availableInvites > 0,
                limitReached: usedInvites >= totalPurchased && totalPurchased > 0,
                hasAnyPurchases: totalPurchased > 0,
                remainingInvites: Math.max(0, totalPurchased - usedInvites)
            });

        } catch (error) {
            console.error("Error checking invite limits:", error);
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            res.status(500).json({ message: "Failed to check invite limits", error: errorMessage });
        }
    });

    // Validate invite code (for signup process)
    app.post("/api/facility/validate-invite", async (req, res) => {
        try {
            const { inviteCode } = req.body;

            if (!inviteCode) {
                res.status(400).json({ message: "Invite code is required" });
                return;
            }

            console.log('Validating invite code:', inviteCode);

            // Find the invite
            const [invite] = await db.select().from(facilityInvites).where(eq(facilityInvites.inviteCode, inviteCode));
            
            if (!invite) {
                return res.status(400).json({ 
                    valid: false, 
                    message: "Invalid invite code" 
                });
            }

            if (invite.status !== 'unused') {
                return res.status(400).json({ 
                    valid: false, 
                    message: "Invite code has already been used" 
                });
            }

            if (invite.expiresAt && new Date() > invite.expiresAt) {
                return res.status(400).json({ 
                    valid: false, 
                    message: "Invite code has expired" 
                });
            }

            // Get the facility
            const [facility] = await db.select().from(facilities).where(eq(facilities.id, invite.facilityId));
            if (!facility) {
                return res.status(400).json({ 
                    valid: false, 
                    message: "Facility not found" 
                });
            }

            console.log('Invite code is valid for facility:', facility.id);

            res.json({
                valid: true,
                message: "Invite code is valid",
                facility: {
                    id: facility.id,
                    name: facility.name,
                    tagline: facility.tagline
                },
                invite: {
                    id: invite.id,
                    expiresAt: invite.expiresAt
                }
            });
        } catch (error) {
            console.error("Error validating invite:", error);
            res.status(500).json({ 
                valid: false, 
                message: "Failed to validate invite" 
            });
        }
    });

    // Validate and use an invite code
    app.post("/api/facility/use-invite", async (req, res) => {
        try {
            const { inviteCode, userEmail, userPhone, userName, userId } = req.body;

            if (!inviteCode) {
                res.status(400).json({ message: "Invite code is required" });
                return;
            }

            let facility;
            
            // If userId is provided, get the facility linked to that user
            if (userId) {
                const [user] = await db.select().from(users).where(eq(users.id, userId));
                if (user?.facilityId) {
                    const [userFacility] = await db.select().from(facilities).where(eq(facilities.id, user.facilityId));
                    facility = userFacility;
                }
            }
            
            // If no facility found from user, fall back to first facility (for backward compatibility)
            if (!facility) {
                const facilities = await storage.getAllFacilities();
                facility = facilities[0];
            }
            
            if (!facility) {
                res.status(404).json({ message: "Facility not found" });
                return;
            }

            console.log('Using invite for facility:', facility.id, 'with user info:', { userEmail, userPhone, userName, userId });

            // Check if facility has reached invite limit
            const purchases = await db
                .select()
                .from(facilityInvitePurchases)
                .where(eq(facilityInvitePurchases.facilityId, facility.id));
            
            let totalPurchased = 0;
            purchases.forEach(purchase => {
                if (purchase.inviteCount && purchase.status === 'completed') {
                    totalPurchased += purchase.inviteCount;
                }
            });

            const allInvites = await db
                .select()
                .from(facilityInvites)
                .where(eq(facilityInvitePurchases.facilityId, facility.id));
            
            const usedInvites = allInvites.filter(invite => invite.status === 'used').length;
            
            if (usedInvites >= totalPurchased && totalPurchased > 0) {
                return res.status(403).json({ 
                    message: "Invitation limit reached. This facility has used all their purchased invites.",
                    limitReached: true,
                    totalPurchased,
                    usedInvites
                });
            }

            // Validate and use the invite
            const result = await storage.useFacilityInvite(inviteCode, facility.id, {
                email: userEmail,
                phone: userPhone,
                name: userName
            });

            if (result.success) {
                res.json({
                    message: "Invite used successfully",
                    facility: result.facility,
                    user: result.user,
                });
            } else {
                res.status(400).json({ message: result.message });
            }
        } catch (error) {
            console.error("Error using invite:", error);
            res.status(500).json({ message: "Failed to use invite" });
        }
    });

    // ==================== Reminder Management ====================== //

    // Get all reminders for a patient
    app.get("/api/patients/:id/reminders", async (req, res) => {
        try {
            const patientId = parseInt(req.params.id);
            if (isNaN(patientId)) {
                res.status(400).json({ message: "Invalid patient ID" });
                return;
            }

            const reminders = await storage.getPatientReminders(patientId);
            res.json(reminders);
        } catch (error) {
            console.error("Error fetching reminders:", error);
            res.status(500).json({ message: "Failed to fetch reminders" });
        }
    });

    // Create a new reminder for a patient
    app.post("/api/patients/:id/reminders", async (req, res) => {
        console.log("POST /api/patients/:id/reminders - Request received");
        console.log("Patient ID:", req.params.id);
        console.log("Request body:", req.body);

        try {
            const patientId = parseInt(req.params.id);
            if (isNaN(patientId)) {
                console.log("Invalid patient ID:", req.params.id);
                res.status(400).json({ message: "Invalid patient ID" });
                return;
            }

            const { message, scheduledTime, createdBy } = req.body;

            // Validate inputs
            if (!message || !scheduledTime || !createdBy) {
                console.log("Missing required fields:", { message, scheduledTime, createdBy });
                res.status(400).json({ message: "Missing required fields: message, scheduledTime, createdBy" });
                return;
            }

            // Validate scheduled time is in the future
            const scheduledDate = new Date(scheduledTime);
            const now = new Date();
            const MIN_FUTURE_MS = 60 * 1000; // 1 minute buffer
            console.log('scheduledDate (UTC):', scheduledDate.toISOString());
            console.log('now (UTC):', now.toISOString());
            if (scheduledDate.getTime() <= now.getTime() + MIN_FUTURE_MS) {
                console.log("Scheduled time is not at least 1 minute in the future:", scheduledDate);
                res.status(400).json({ message: "Scheduled time must be at least 1 minute in the future" });
                return;
            }

            console.log("Creating reminder with data:", { patientId, createdBy, message, scheduledTime: scheduledDate });
            const reminder = await storage.createReminder({
                patientId,
                createdBy,
                message,
                scheduledTime: scheduledDate,
            });

            console.log("Reminder created successfully:", reminder);
            res.status(201).json(reminder);
        } catch (error) {
            console.error("Error creating reminder:", error);
            res.status(500).json({ message: "Failed to create reminder" });
        }
    });

    // Update a reminder
    app.put("/api/reminders/:id", async (req, res) => {
        try {
            const reminderId = parseInt(req.params.id);
            if (isNaN(reminderId)) {
                res.status(400).json({ message: "Invalid reminder ID" });
                return;
            }

            const { message, scheduledTime, isActive } = req.body;
            const updateData: any = {};

            if (message !== undefined) updateData.message = message;
            if (scheduledTime !== undefined) {
                const scheduledDate = new Date(scheduledTime);
                if (scheduledDate <= new Date()) {
                    res.status(400).json({ message: "Scheduled time must be in the future" });
                    return;
                }
                updateData.scheduledTime = scheduledDate;
            }
            if (isActive !== undefined) updateData.isActive = isActive;

            updateData.updatedAt = new Date();

            const reminder = await storage.updateReminder(reminderId, updateData);
            res.json(reminder);
        } catch (error) {
            console.error("Error updating reminder:", error);
            res.status(500).json({ message: "Failed to update reminder" });
        }
    });

    // Delete a reminder
    app.delete("/api/reminders/:id", async (req, res) => {
        try {
            const reminderId = parseInt(req.params.id);
            if (isNaN(reminderId)) {
                res.status(400).json({ message: "Invalid reminder ID" });
                return;
            }

            await storage.deleteReminder(reminderId);
            res.status(204).send();
        } catch (error) {
            console.error("Error deleting reminder:", error);
            res.status(500).json({ message: "Failed to delete reminder" });
        }
    });

    // Mark reminder as completed
    app.post("/api/reminders/:id/complete", async (req, res) => {
        try {
            const reminderId = parseInt(req.params.id);
            if (isNaN(reminderId)) {
                res.status(400).json({ message: "Invalid reminder ID" });
                return;
            }

            await storage.markReminderAsCompleted(reminderId);
            res.json({ message: "Reminder marked as completed" });
        } catch (error) {
            console.error("Error completing reminder:", error);
            res.status(500).json({ message: "Failed to complete reminder" });
        }
    });

    // Get active reminders for a patient (for notifications)
    app.get("/api/patients/:id/reminders/active", async (req, res) => {
        try {
            const patientId = parseInt(req.params.id);
            if (isNaN(patientId)) {
                res.status(400).json({ message: "Invalid patient ID" });
                return;
            }

            const reminders = await storage.getActiveRemindersForPatient(patientId);
            res.json(reminders);
        } catch (error) {
            console.error("Error fetching active reminders:", error);
            res.status(500).json({ message: "Failed to fetch active reminders" });
        }
    });

    // ==================== Patient Management ====================== //

    // ==================== Billing Success/Cancel Pages ====================== //

    // Success page for family member payments
    app.get("/billing/success", async (req: Request, res: Response): Promise<any> => {
        try {
            const { session_id } = req.query;
            
            if (!session_id) {
                return res.status(400).json({ message: "Session ID is required" });
            }

            // Retrieve the checkout session to get payment details
            const session = await stripe.checkout.sessions.retrieve(session_id as string);
            
            if (!session) {
                return res.status(404).json({ message: "Session not found" });
            }

            // Get customer details
            let customer: Stripe.Customer | null = null;
            if (session.customer) {
                const customerResponse = await stripe.customers.retrieve(session.customer as string);
                if (customerResponse && !customerResponse.deleted) {
                    customer = customerResponse;
                }
            }

            // Get subscription details if it's a subscription
            let subscription = null;
            if (session.subscription) {
                subscription = await stripe.subscriptions.retrieve(session.subscription as string);
            }

            // Send HTML response for success page
            const successHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Payment Successful - CalmPath AI</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 40px;
            text-align: center;
            max-width: 500px;
            width: 100%;
        }
        
        .success-icon {
            width: 80px;
            height: 80px;
            background: #10b981;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 30px;
            color: white;
            font-size: 40px;
        }
        
        h1 {
            color: #1f2937;
            margin-bottom: 20px;
            font-size: 28px;
        }
        
        .message {
            color: #6b7280;
            margin-bottom: 30px;
            line-height: 1.6;
        }
        
        .details {
            background: #f9fafb;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 30px;
            text-align: left;
        }
        
        .detail-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
            padding-bottom: 10px;
            border-bottom: 1px solid #e5e7eb;
        }
        
        .detail-row:last-child {
            border-bottom: none;
            margin-bottom: 0;
        }
        
        .detail-label {
            font-weight: 600;
            color: #374151;
        }
        
        .detail-value {
            color: #6b7280;
        }
        
        .buttons {
            display: flex;
            gap: 15px;
            justify-content: center;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 12px 24px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
            font-size: 14px;
        }
        
        .btn-primary {
            background: #667eea;
            color: white;
        }
        
        .btn-primary:hover {
            background: #5a67d8;
            transform: translateY(-2px);
        }
        
        .btn-secondary {
            background: #f3f4f6;
            color: #374151;
        }
        
        .btn-secondary:hover {
            background: #e5e7eb;
            transform: translateY(-2px);
        }
        
        @media (max-width: 480px) {
            .container {
                padding: 30px 20px;
            }
            
            .buttons {
                flex-direction: column;
            }
            
            .btn {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">✓</div>
        <h1>Payment Successful!</h1>
        <p class="message">
            Thank you for your payment. Your family member's subscription has been activated successfully.
            You will receive a confirmation email shortly.
        </p>
        
        <div class="details">
            <div class="detail-row">
                <span class="detail-label">Session ID:</span>
                <span class="detail-value">${session.id}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Amount:</span>
                <span class="detail-value">$${(session.amount_total! / 100).toFixed(2)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Status:</span>
                <span class="detail-value">${session.payment_status}</span>
            </div>
            ${customer ? `
            <div class="detail-row">
                <span class="detail-label">Customer:</span>
                <span class="detail-value">${customer.email || 'N/A'}</span>
            </div>
            ` : ''}
            ${subscription ? `
            <div class="detail-row">
                <span class="detail-label">Subscription:</span>
                <span class="detail-value">${subscription.status}</span>
            </div>
            ` : ''}
        </div>
        
        <div class="buttons">
            <a href="/family-dashboard" class="btn btn-primary">Go to Dashboard</a>
            <a href="/" class="btn btn-secondary">Back to Home</a>
        </div>
    </div>
</body>
</html>`;

            res.setHeader('Content-Type', 'text/html');
            res.send(successHtml);
        } catch (err: any) {
            console.error("Success page error:", err);
            res.status(500).json({
                message: "Failed to load success page",
                error: err.message
            });
        }
    });

    // JSON API endpoint for payment details (for frontend use)
    app.get("/api/billing/payment-details", async (req: Request, res: Response): Promise<any> => {
        try {
            const { session_id } = req.query;
            
            if (!session_id) {
                return res.status(400).json({ error: "Session ID is required" });
            }

            // Retrieve the checkout session to get payment details
            const session = await stripe.checkout.sessions.retrieve(session_id as string);
            
            if (!session) {
                return res.status(404).json({ error: "Session not found" });
            }

            // Get customer details
            let customer: Stripe.Customer | null = null;
            if (session.customer) {
                const customerResponse = await stripe.customers.retrieve(session.customer as string);
                if (customerResponse && !customerResponse.deleted) {
                    customer = customerResponse;
                }
            }

            // Get subscription details if it's a subscription
            let subscription = null;
            if (session.subscription) {
                subscription = await stripe.subscriptions.retrieve(session.subscription as string);
            }

            // Format the response
            const paymentDetails = {
                sessionId: session.id,
                amount: session.amount_total ? `$${(session.amount_total / 100).toFixed(2)}` : 'N/A',
                status: session.payment_status || 'unknown',
                customerEmail: customer?.email || null,
                subscriptionStatus: subscription?.status || null,
                currency: session.currency?.toUpperCase() || 'USD',
                createdAt: session.created,
                metadata: session.metadata || {},
            };

            res.json(paymentDetails);
        } catch (err: any) {
            console.error("Payment details API error:", err);
            res.status(500).json({
                error: "Failed to fetch payment details",
                message: err.message
            });
        }
    });

    // Cancel page for family member payments
    app.get("/billing/cancel", async (req: Request, res: Response): Promise<any> => {
        try {
            // Send HTML response for cancel page
            const cancelHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Payment Cancelled - CalmPath AI</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 40px;
            text-align: center;
            max-width: 500px;
            width: 100%;
        }
        
        .cancel-icon {
            width: 80px;
            height: 80px;
            background: #ef4444;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 30px;
            color: white;
            font-size: 40px;
        }
        
        h1 {
            color: #1f2937;
            margin-bottom: 20px;
            font-size: 28px;
        }
        
        .message {
            color: #6b7280;
            margin-bottom: 30px;
            line-height: 1.6;
        }
        
        .info-box {
            background: #fef2f2;
            border: 1px solid #fecaca;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 30px;
        }
        
        .info-title {
            color: #dc2626;
            font-weight: 600;
            margin-bottom: 10px;
        }
        
        .info-text {
            color: #6b7280;
            line-height: 1.6;
        }
        
        .buttons {
            display: flex;
            gap: 15px;
            justify-content: center;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 12px 24px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
            font-size: 14px;
        }
        
        .btn-primary {
            background: #f093fb;
            color: white;
        }
        
        .btn-primary:hover {
            background: #e879f9;
            transform: translateY(-2px);
        }
        
        .btn-secondary {
            background: #f3f4f6;
            color: #374151;
        }
        
        .btn-secondary:hover {
            background: #e5e7eb;
            transform: translateY(-2px);
        }
        
        @media (max-width: 480px) {
            .container {
                padding: 30px 20px;
            }
            
            .buttons {
                flex-direction: column;
            }
            
            .btn {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="cancel-icon">✕</div>
        <h1>Payment Cancelled</h1>
        <p class="message">
            Your payment was cancelled. No charges have been made to your account.
            You can try again anytime or contact our support team for assistance.
        </p>
        
        <div class="info-box">
            <div class="info-title">What happened?</div>
            <div class="info-text">
                The payment process was interrupted or cancelled. This could be due to:
                <ul style="text-align: left; margin-top: 10px; padding-left: 20px;">
                    <li>You closed the payment window</li>
                    <li>Network connectivity issues</li>
                    <li>Payment method was declined</li>
                    <li>You decided to cancel the transaction</li>
                </ul>
            </div>
        </div>
        
        <div class="buttons">
            <a href="/family-dashboard" class="btn btn-primary">Try Again</a>
            <a href="/" class="btn btn-secondary">Back to Home</a>
        </div>
    </div>
</body>
</html>`;

            res.setHeader('Content-Type', 'text/html');
            res.send(cancelHtml);
        } catch (err: any) {
            console.error("Cancel page error:", err);
            res.status(500).json({
                message: "Failed to load cancel page",
                error: err.message
            });
        }
    });

    const httpServer = createServer(app);
    return httpServer;
}