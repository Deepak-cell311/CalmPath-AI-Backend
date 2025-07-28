import "dotenv/config"
import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { therapeuticAI } from "./services/openai";
import multer from "multer";
import path from "path";
import express, { Request, Response } from "express";
import { createUser, getUserByEmail, User } from "./auth";
import { setupAuth, isAuthenticated } from "./auth/middleware";
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
    insertMedicationSchema
} from "../shared/schema";
import { Methods } from "openai/resources/fine-tuning/methods";
import { randomUUID } from "crypto";
import { db } from "./db";

declare module 'express-session' {
    interface SessionData {
        user?: User;
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
        fileSize: 5 * 1024 * 1024, // 5MB limit
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

    // --- Session: Use secure cookies and correct SameSite for production ---
    app.use(session({
        store: new (connectPgSimple(session))({
            conObject: {
                connectionString: process.env.DATABASE_URL,
            },
            tableName: 'express_sessions',
        }),
        secret: "repair-request-secret",
        resave: false,
        saveUninitialized: false,
        cookie: { secure: true, sameSite: "none" }
    }));

    app.get("/api/health", (req, res) => {
        res.json({ status: "ok" });
    });

    app.use('/uploads', express.static(path.join(__dirname, 'uploads')));  // Serve static files from the uploads directory

    setupAuth(app);

    app.get('/api/auth/user',  async (req: Request, res: Response) => {
        try {
            const userId = req.user.id;
            const user = await storage.getUser(userId);
            res.json(user);
        } catch (error) {
            console.error("Error fetching user:", error);
            res.status(500).json({ message: "Failed to fetch user" });
        }
    });




    // =============== Patients API / Routes ================== //

    // Get all patients
    app.get("/api/patients",  async (req, res) => {
        try {
            const patients = await storage.getAllPatients();
            res.json(patients);
        } catch (error) {
            console.error("Error fetching patients:", error);
            res.status(500).json({ message: "Failed to fetch patients" });
        }
    });

    // Get a specific patient by ID
    app.get("/api/patients/:id",  async (req, res) => {
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
    app.post("/api/patients",  async (req, res) => {
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
    app.patch("/api/patients/:id/status",  async (req, res) => {
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
    app.patch("/api/patients/:id/interaction",  async (req, res) => {
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
    app.get("/api/patients/:id/notes",  async (req, res) => {
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
    app.post("/api/patients/:id/notes",  async (req, res) => {
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
    app.get("/api/patients/:id/mood-history",  async (req, res) => {
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
    app.post("/api/patients/:id/conversation",  async (req, res) => {
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
    app.get("/api/patients/:id/photos",  async (req, res) => {
        try {
            const patientId = parseInt(req.params.id);
            const photos = await storage.getPatientPhotos(patientId);
            res.json(photos);
        } catch (error) {
            console.error("Error fetching therapeutic photos:", error);
            res.status(500).json({ message: "Failed to fetch photos" });
        }
    });


    app.post("/api/family/memoryPhotos",  upload.single("photo"), async (req: Request, res: Response): Promise<any> => {
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

    app.get("/api/family/memoryPhotos",  async (req: Request, res: Response): Promise<any> => {
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

    app.delete("/api/family/memoryPhotos/:id",  async (req: Request, res: Response): Promise<any> => {
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

    app.post("/api/patients/:id/photos",  upload.single('photo'), async (req: Request, res: Response) => {
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
    app.delete("/api/photos/:id",  async (req, res) => {
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
    app.get("/api/alerts",  async (req, res) => {
        try {
            const alerts = await storage.getUnreadAlerts();
            res.json(alerts);
        } catch (error) {
            console.error("Error fetching alerts:", error);
            res.status(500).json({ message: "Failed to fetch alerts" });
        }
    });

    // Mark alert as read
    app.patch("/api/alerts/:id/read",  async (req, res) => {
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
    app.get("/api/analytics/status-counts",  async (req, res) => {
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
        patientAccessCode: z.string().optional(),
        facilityId: z.union([z.string(), z.number()]).optional(),
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
                field: parsed.error.errors[0].path[0],
                message: parsed.error.errors[0].message,
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
            patientAccessCode,
            facilityId,
            facilityName,
            roomNumber,
            care_level,
        } = parsed.data;

        const normalizedPhone = phoneNumber.trim();
        const passwordHash = await bcrypt.hash(password, 10);
        const userId = randomUUID();

        try {
            // Check if user already exists
            const existing = await db.select().from(users).where(eq(users.phoneNumber, normalizedPhone));
            if (existing.length > 0) {
                return res.status(409).json({ message: "Phone number already registered" });
            }

            // Facility Staff logic
            let facilityStaffFacilityId = null;
            if (accountType === "Facility Staff") {
                if (!facilityId || !facilityName) {
                    return res.status(400).json({ message: "Facility ID and Facility Name are required for Facility Staff" });
                }
                // Check if facility exists
                let facilityRecord = await db.select().from(facilities).where(eq(facilities.id, String(facilityId)));
                if (facilityRecord.length === 0) {
                    // Facility does not exist, create it
                    await db.insert(facilities).values({
                        id: String(facilityId),
                        name: facilityName,
                        // Add other required fields if needed
                    });
                }
                facilityStaffFacilityId = String(facilityId);
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
                    patientAccessCode: accountType === "Family Member" ? patientAccessCode : null,
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
                    facilityId: facilityId != null ? String(facilityId) : null,
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
            const { accountType, email, password } = req.body;

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

            // Save session
            req.session.user = {
                ...user,
                userId: user.id,
            };

            console.log("Session set:", req.session.user);

            res.json({
                success: true,
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.firstName,
                    accountType: user.accountType
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

            res.json({
                success: true,
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.firstName,
                    accountType: user.accountType
                }
            });
        } catch (error) {
            console.error('Facility login error:', error);
            res.status(500).json({ error: 'Login failed' });
        }
    });

    // Get current user
    app.get('/api/auth/currentUser', (req, res) => {
        const user = req.session?.user;

        if (user) {
            res.json({
                id: user.id,
                email: user.email,
                name: user.firstName,
                accountType: user.accountType
            });
        } else {
            res.status(401).json({ error: 'Not authenticated' });
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
    app.post("/api/chat",  async (req: Request, res: Response): Promise<any> => {
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
    app.get("/api/patients/:id/medications",  async (req, res) => {
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
    app.post("/api/patients/:id/medications",  async (req, res) => {
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
    app.delete("/api/medications/:id",  async (req, res) => {
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
    app.post("/api/billing/checkout-session", isAuthenticated, async (req: Request, res: Response): Promise<any> => {
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
    app.post("/api/billing/portal-session", isAuthenticated, async (req: Request, res: Response): Promise<any> => {
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
    app.get("/api/billing/subscription", isAuthenticated, async (req: Request, res: Response): Promise<any> => {
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
    app.post("/api/billing/cancel-subscription", isAuthenticated, async (req: Request, res: Response): Promise<any> => {
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
            await storage.updateUserSubscriptionStatus (userId, subscription.status);

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
    app.post("/api/billing/reactivate-subscription", isAuthenticated, async (req: Request, res: Response): Promise<any> => {
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
    app.get("/api/billing/invoices", isAuthenticated, async (req: Request, res: Response): Promise<any> => {
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
    app.post("/api/billing/customer", isAuthenticated, async (req: Request, res: Response): Promise<any> => {
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
    app.post("/api/billing/payment-method", isAuthenticated, async (req: Request, res: Response): Promise<any> => {
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
    app.get("/api/billing/payment-methods", isAuthenticated, async (req: Request, res: Response): Promise<any> => {
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
                    console.log('❌ Subscription deleted:', deletedSubscription.id);
                    
                    const deletedUserId = deletedSubscription.metadata?.userId;
                    if (deletedUserId) {
                        await storage.updateUserSubscriptionStatus(deletedUserId, 'canceled');
                    }
                    break;

                case 'invoice.payment_succeeded':
                    const invoice = event.data.object as Stripe.Invoice;
                    console.log('💰 Invoice payment succeeded:', invoice.id);
                    break;

                case 'invoice.payment_failed':
                    const failedInvoice = event.data.object as Stripe.Invoice;
                    console.log('❌ Invoice payment failed:', failedInvoice.id);
                    
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
    app.get("/api/facility", async (req, res) => {
        try {
            const facilities = await storage.getAllFacilities();
            const facility = facilities[0]; // For now, get the first facility
            res.json(facility || {});
        } catch (error) {
            console.error("Error fetching facility:", error);
            res.status(500).json({ message: "Failed to fetch facility" });
        }
    });

    // Update facility information
    app.post("/api/facility", async (req, res) => {
        try {
            const { name, address, phone, email } = req.body;
            const facility = await storage.updateFacility({
                name,
                address,
                phone,
                adminEmail: email,
            });
            res.json(facility);
        } catch (error) {
            console.error("Error updating facility:", error);
            res.status(500).json({ message: "Failed to update facility" });
        }
    });

    // Get facility billing settings
    app.get("/api/facility/billing", async (req, res) => {
        try {
            const facilities = await storage.getAllFacilities();
            const facility = facilities[0]; // For now, get the first facility
            res.json({
                monthlyPrice: facility?.subscriptionTier === "premium" ? "25" : "15",
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
    app.post("/api/facility/billing", async (req, res) => {
        try {
            const { monthlyPrice, promoCode } = req.body;
            
            // Validate inputs
            if (!monthlyPrice || isNaN(Number(monthlyPrice))) {
                res.status(400).json({ message: "Invalid monthly price" });
                return;
            }

            const facilities = await storage.getAllFacilities();
            const facility = facilities[0]; // For now, get the first facility
            
            if (!facility) {
                res.status(404).json({ message: "Facility not found" });
                return;
            }

            // Create or update Stripe product and price
            let stripeProductId = facility.stripeProductId;
            let stripePriceId = facility.stripePriceId;

            if (!stripeProductId) {
                // Create new Stripe product
                const product = await stripe.products.create({
                    name: `${facility.name} Subscription`,
                    description: `Monthly subscription for ${facility.name}`,
                    metadata: {
                        facilityId: facility.id,
                    },
                });
                stripeProductId = product.id;
            }

            // Create new price for the product
            const price = await stripe.prices.create({
                product: stripeProductId,
                unit_amount: Number(monthlyPrice) * 100, // Convert to cents
                currency: 'usd',
                recurring: {
                    interval: 'month',
                },
                metadata: {
                    facilityId: facility.id,
                },
            });
            stripePriceId = price.id;

            // Create or update Stripe coupon if promo code provided
            let stripeCouponId = null;
            if (promoCode && promoCode.trim()) {
                try {
                    // Check if coupon already exists
                    const existingCoupons = await stripe.coupons.list({ limit: 100 });
                    const existingCoupon = existingCoupons.data.find(c => c.name === promoCode);
                    
                    if (existingCoupon) {
                        stripeCouponId = existingCoupon.id;
                    } else {
                        // Create new coupon
                        const coupon = await stripe.coupons.create({
                            name: promoCode,
                            percent_off: 100, // 100% off for free access
                            duration: 'forever',
                            metadata: {
                                facilityId: facility.id,
                            },
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

    // ==================== Patient Management ====================== //

    const httpServer = createServer(app);
    return httpServer;
}