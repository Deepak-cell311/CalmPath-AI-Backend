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
import { eq } from "drizzle-orm";
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
            const token = Buffer.from(JSON.stringify({
                userId: user.id,
                email: user.email,
                timestamp: Date.now()
            })).toString('base64');

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

                const user = await storage.getUser(userId);

                if (!user) {
                    return res.status(404).json({ message: "User not found" });
                }

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

    app.use('/uploads', express.static(path.join(__dirname, 'uploads')));  // Serve static files from the uploads directory

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

            const photoUrl = `/uploads/${req.file.filename}`;

            const schema = z.object({
                file: z.string().url(),
                photoname: z.string().optional(),
                description: z.string().optional(),
                tags: z.array(z.string()).optional(),
                contextAndStory: z.string().optional(),
            });

            const validatedData = schema.parse({
                file: `${req.protocol}://${req.get("host")}${photoUrl}`,
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
            if (!id) {
                return res.status(400).json({ message: "No id provided" });
            }
            // Find the photo to get the file path
            const photo = await db.query.memoryPhotos.findFirst({ where: (photo, { eq }) => eq(photo.id, id) });
            if (!photo) {
                return res.status(404).json({ message: "Photo not found" });
            }
            // Delete from DB
            await db.delete(memoryPhotos).where(eq(memoryPhotos.id, id));
            // Delete file from disk
            if (photo.file) {
                const fs = require('fs');
                const path = require('path');
                const filePath = path.join(__dirname, '../uploads', path.basename(photo.file));
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath);
                }
            }
            return res.status(200).json({ message: "Photo deleted" });
        } catch (error: any) {
            console.error("Error deleting memory photo:", error);
            return res.status(500).json({ message: "Failed to delete memory photo", error: error.message });
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
                    const facilities = await storage.getAllFacilities();
                    const facility = facilities[0]; // For now, get the first facility

                    if (!facility) {
                        res.status(500).json({ error: 'No facility found' });
                        return;
                    }

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

                    // Update user to mark that they used an invite code
                    await db.update(users)
                        .set({
                            usedInviteCode: true,
                            updatedAt: new Date()
                        })
                        .where(eq(users.id, user.id));

                    console.log("User used invite code successfully:", user.id);
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

            // Check account type match
            // Allow Family Members to login as Patient (for dual access)
            if (user.accountType !== accountType) {
                // Special case: Family Member can login as Patient
                if (!(user.accountType === "Family Member" && accountType === "Patient")) {
                    res.status(403).json({ error: 'Account type mismatch' });
                    return;
                }
            }

            // Get facilities
            const facilities = await storage.getAllFacilities();
            const facility = facilities[0]; // For now, get the first facility

            if (!facility) {
                res.status(500).json({ error: 'No facility found' });
                return;
            }

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

            // Update user to mark that they used an invite code
            await db.update(users)
                .set({
                    usedInviteCode: true,
                    updatedAt: new Date()
                })
                .where(eq(users.id, user.id));

            // Generate a simple token
            const token = Buffer.from(JSON.stringify({
                userId: user.id,
                email: user.email,
                timestamp: Date.now()
            })).toString('base64');

            console.log("Invite login successful:", user.id);

            res.json({
                success: true,
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.firstName,
                    accountType: user.accountType,
                    usedInviteCode: true
                },
                token: token
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
            const userId = req.user?.id;

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
            const userId = req.user?.id;

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
            const userId = req.user?.id;
            const user = await storage.getUser(userId);

            if (!user?.stripeSubscriptionId) {
                return res.status(404).json({ message: "No active subscription found" });
            }

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
                        priceId: item.price.id,
                        quantity: item.quantity,
                    })),
                }
            });
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
            const userId = req.user?.id;
            const { cancelAtPeriodEnd = true } = req.body;

            const user = await storage.getUser(userId);

            if (!user?.stripeSubscriptionId) {
                return res.status(404).json({ message: "No active subscription found" });
            }

            const subscription = await stripe.subscriptions.update(user.stripeSubscriptionId, {
                cancel_at_period_end: cancelAtPeriodEnd,
            });

            // Update user subscription status in database
            await storage.updateUserSubscriptionStatus(userId, subscription.status);

            res.json({
                message: "Subscription cancelled successfully",
                cancelAtPeriodEnd: (subscription as any).cancel_at_period_end,
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
            const userId = req.user?.id;
            const user = await storage.getUser(userId);

            if (!user?.stripeSubscriptionId) {
                return res.status(404).json({ message: "No subscription found" });
            }

            const subscription = await stripe.subscriptions.update(user.stripeSubscriptionId, {
                cancel_at_period_end: false,
            });

            // Update user subscription status in database
            await storage.updateUserSubscriptionStatus(userId, subscription.status);

            res.json({
                message: "Subscription reactivated successfully",
                cancelAtPeriodEnd: (subscription as any).cancel_at_period_end,
            });
        } catch (err: any) {
            console.error("Subscription reactivation error:", err);
            res.status(500).json({
                message: "Failed to reactivate subscription",
                error: err.message
            });
        }
    });

    // Get billing history
    app.get("/api/billing/invoices", isAuthenticatedToken, async (req: Request, res: Response): Promise<any> => {
        try {
            const userId = req.user?.id;
            const user = await storage.getUser(userId);

            if (!user?.stripeCustomerId) {
                return res.status(404).json({ message: "No billing account found" });
            }

            const invoices = await stripe.invoices.list({
                customer: user.stripeCustomerId,
                limit: 12, // Last 12 invoices
            });

            res.json({
                invoices: invoices.data.map(invoice => ({
                    id: invoice.id,
                    number: invoice.number,
                    amountDue: invoice.amount_due,
                    amountPaid: invoice.amount_paid,
                    status: invoice.status,
                    created: invoice.created,
                    dueDate: invoice.due_date,
                    pdf: invoice.invoice_pdf,
                }))
            });
        } catch (err: any) {
            console.error("Invoice retrieval error:", err);
            res.status(500).json({
                message: "Failed to retrieve invoices",
                error: err.message
            });
        }
    });

    // Get available plans/prices
    app.get("/api/billing/prices", async (req: Request, res: Response) => {
        try {
            const prices = await stripe.prices.list({
                active: true,
                expand: ['data.product'],
            });

            res.json({
                prices: prices.data.map(price => ({
                    id: price.id,
                    unitAmount: price.unit_amount,
                    currency: price.currency,
                    recurring: price.recurring,
                    product: price.product as Stripe.Product,
                }))
            });
        } catch (err: any) {
            console.error("Price retrieval error:", err);
            res.status(500).json({
                message: "Failed to retrieve prices",
                error: err.message
            });
        }
    });

    // Create customer
    app.post("/api/billing/customer", isAuthenticatedToken, async (req: Request, res: Response): Promise<any> => {
        try {
            const userId = req.user?.id;
            const { email, name, phone } = req.body;

            const user = await storage.getUser(userId);
            if (user?.stripeCustomerId) {
                return res.status(400).json({ message: "Customer already exists" });
            }

            const customer = await stripe.customers.create({
                email,
                name,
                phone,
                metadata: {
                    userId: userId,
                },
            });

            // Update user with Stripe customer ID
            await storage.updateUserStripeCustomerId(userId, customer.id);

            res.json({
                customerId: customer.id,
                message: "Customer created successfully",
            });
        } catch (err: any) {
            console.error("Customer creation error:", err);
            res.status(500).json({
                message: "Failed to create customer",
                error: err.message
            });
        }
    });

    // Update payment method
    app.post("/api/billing/payment-method", isAuthenticatedToken, async (req: Request, res: Response): Promise<any> => {
        try {
            const userId = req.user?.id;
            const { paymentMethodId } = req.body;

            const user = await storage.getUser(userId);
            if (!user?.stripeCustomerId) {
                return res.status(404).json({ message: "No billing account found" });
            }

            // Attach payment method to customer
            await stripe.paymentMethods.attach(paymentMethodId, {
                customer: user.stripeCustomerId,
            });

            // Set as default payment method
            await stripe.customers.update(user.stripeCustomerId, {
                invoice_settings: {
                    default_payment_method: paymentMethodId,
                },
            });

            res.json({ message: "Payment method updated successfully" });
        } catch (err: any) {
            console.error("Payment method update error:", err);
            res.status(500).json({
                message: "Failed to update payment method",
                error: err.message
            });
        }
    });

    // Get payment methods
    app.get("/api/billing/payment-methods", isAuthenticatedToken, async (req: Request, res: Response): Promise<any> => {
        try {
            const userId = req.user?.id;
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
                    brand: pm.card?.brand,
                    last4: pm.card?.last4,
                    expMonth: pm.card?.exp_month,
                    expYear: pm.card?.exp_year,
                    isDefault: pm.id === user.stripeCustomerId, // This would need to be tracked separately
                }))
            });
        } catch (err: any) {
            console.error("Payment methods retrieval error:", err);
            res.status(500).json({
                message: "Failed to retrieve payment methods",
                error: err.message
            });
        }
    });

    // Webhook handler for Stripe events
    app.post("/api/billing/webhook", express.raw({ type: 'application/json' }), async (req: Request, res: Response): Promise<any> => {
        const sig = req.headers['stripe-signature'];
        const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET!;

        let event: Stripe.Event;

        try {
            event = stripe.webhooks.constructEvent(req.body, sig as string, endpointSecret);
        } catch (err: any) {
            console.error('Webhook signature verification failed:', err.message);
            res.status(400).send(`Webhook Error: ${err.message}`);
            return;
        }

        try {
            switch (event.type) {
                case 'checkout.session.completed':
                    const session = event.data.object as Stripe.Checkout.Session;
                    console.log('✅ Checkout session completed:', session.id);

                    if (session.subscription && session.customer) {
                        const userId = session.metadata?.userId;
                        if (userId) {
                            await storage.updateUserStripeCustomerId(userId, session.customer as string);
                            await storage.updateUserStripeSubscriptionId(userId, session.subscription as string);
                            await storage.updateUserSubscriptionStatus(userId, 'active');
                        }
                    }
                    break;

                case 'customer.subscription.updated':
                    const subscription = event.data.object as Stripe.Subscription;
                    console.log('📝 Subscription updated:', subscription.id);

                    const subUserId = subscription.metadata?.userId;
                    if (subUserId) {
                        await storage.updateUserSubscriptionStatus(subUserId, subscription.status);
                    }
                    break;

                case 'customer.subscription.deleted':
                    const deletedSubscription = event.data.object as Stripe.Subscription;
                    console.log('Subscription deleted:', deletedSubscription.id);

                    const deletedUserId = deletedSubscription.metadata?.userId;
                    if (deletedUserId) {
                        await storage.updateUserSubscriptionStatus(deletedUserId, 'canceled');
                    }
                    break;

                case 'invoice.payment_succeeded':
                    const invoice = event.data.object as Stripe.Invoice;
                    console.log('Invoice payment succeeded:', invoice.id);
                    break;

                case 'invoice.payment_failed':
                    const failedInvoice = event.data.object as Stripe.Invoice;
                    console.log('Invoice payment failed:', failedInvoice.id);

                    const failedUserId = failedInvoice.metadata?.userId;
                    if (failedUserId) {
                        await storage.updateUserSubscriptionStatus(failedUserId, 'past_due');
                    }
                    break;

                default:
                    console.log(`Unhandled event type: ${event.type}`);
            }

            res.json({ received: true });
        } catch (err: any) {
            console.error('Webhook handler error:', err);
            res.status(500).json({ error: 'Webhook handler failed' });
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
    app.post("/api/facility/logo", upload.single("logo"), (req, res): void => {
        if (!req.file) {
            res.status(400).json({ message: "No file uploaded" });
            return;
        }
        // Return the URL to the uploaded file
        const logoUrl = `/uploads/${req.file.filename}`;
        res.json({ logoUrl });
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

    // Validate and use an invite code
    app.post("/api/facility/use-invite", async (req, res) => {
        try {
            const { inviteCode, userEmail, userPhone, userName } = req.body;

            if (!inviteCode) {
                res.status(400).json({ message: "Invite code is required" });
                return;
            }

            const facilities = await storage.getAllFacilities();
            const facility = facilities[0]; // For now, get the first facility
            if (!facility) {
                res.status(404).json({ message: "Facility not found" });
                return;
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
                    // patient: result?.patient
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

    const httpServer = createServer(app);
    return httpServer;
}