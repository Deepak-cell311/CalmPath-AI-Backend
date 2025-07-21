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
import cors from "cors";
import bcrypt from "bcryptjs";
import z from "zod";
import { eq } from "drizzle-orm";

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
  app.use(cors(
    {
      // origin: 'https://calm-path-ai.vercel.app',
      origin: 'http://localhost:3000',
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
      credentials: true
    }
  )); // Allow all origins

  app.get("/api/health", (req, res) => {
    res.json({ status: "ok" });
  });

  app.use('/uploads', express.static(path.join(__dirname, 'uploads')));  // Serve static files from the uploads directory


  app.use(session({
    secret: "hello world", // use a strong secret in production!
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // set to true if using HTTPS
      sameSite: "lax"
    }
  }));

  setupAuth(app);

  app.get('/api/auth/user', isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = req.user.id; // Use id from session user
      const user = await storage.getUser(userId);
      res.json(user);
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });




  // =============== Patients API / Routes ================== //

  // Get all patients
  app.get("/api/patients", isAuthenticated, async (req, res) => {
    try {
      const patients = await storage.getAllPatients();
      res.json(patients);
    } catch (error) {
      console.error("Error fetching patients:", error);
      res.status(500).json({ message: "Failed to fetch patients" });
    }
  });

  // Get a specific patient by ID
  app.get("/api/patients/:id", isAuthenticated, async (req, res) => {
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
  app.post("/api/patients", isAuthenticated, async (req, res) => {
    try {
      const validatedData = insertPatientSchema.parse(req.body);
      const patient = await storage.createPatient(validatedData);
      res.json(patient);
    } catch (error) {
      console.error("Error creating patient:", error);
      res.status(400).json({ message: "Invalid patient data" });
    }
  });

  // Update patient status (e.g., anxious, ok, good)
  app.patch("/api/patients/:id/status", isAuthenticated, async (req, res) => {
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
  app.patch("/api/patients/:id/interaction", isAuthenticated, async (req, res) => {
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
  app.get("/api/patients/:id/notes", isAuthenticated, async (req, res) => {
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
  app.post("/api/patients/:id/notes", isAuthenticated, async (req, res) => {
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
  app.get("/api/patients/:id/mood-history", isAuthenticated, async (req, res) => {
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
  app.post("/api/patients/:id/conversation", isAuthenticated, async (req, res) => {
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
  app.get("/api/patients/:id/photos", isAuthenticated, async (req, res) => {
    try {
      const patientId = parseInt(req.params.id);
      const photos = await storage.getPatientPhotos(patientId);
      res.json(photos);
    } catch (error) {
      console.error("Error fetching therapeutic photos:", error);
      res.status(500).json({ message: "Failed to fetch photos" });
    }
  });


  app.post("/api/family/memoryPhotos", isAuthenticated, upload.single("photo"), async (req: Request, res: Response): Promise<any> => {
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

  app.get("/api/family/memoryPhotos", isAuthenticated, async (req: Request, res: Response):Promise<any> => {
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

  app.post("/api/patients/:id/photos", isAuthenticated, upload.single('photo'), async (req: Request, res: Response) => {
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
  app.delete("/api/photos/:id", isAuthenticated, async (req, res) => {
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
  app.get("/api/alerts", isAuthenticated, async (req, res) => {
    try {
      const alerts = await storage.getUnreadAlerts();
      res.json(alerts);
    } catch (error) {
      console.error("Error fetching alerts:", error);
      res.status(500).json({ message: "Failed to fetch alerts" });
    }
  });

  // Mark alert as read
  app.patch("/api/alerts/:id/read", isAuthenticated, async (req, res) => {
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
  app.get("/api/analytics/status-counts", isAuthenticated, async (req, res) => {
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
  app.post("/api/chat", isAuthenticated, async (req: Request, res: Response):Promise<any> => {
    try {
      const { message, conversationHistory } = req.body;
      if (!message) {
        return res.status(400).json({ message: "Message is required" });
      }

      const aiResult = await therapeuticAI.generateResponse(message, conversationHistory );

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
  app.get("/api/patients/:id/medications", isAuthenticated, async (req, res) => {
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
  app.post("/api/patients/:id/medications", isAuthenticated, async (req, res) => {
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
  app.delete("/api/medications/:id", isAuthenticated, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      await storage.deleteMedication(id);
      res.json({ message: "Medication deleted successfully" });
    } catch (error) {
      console.error("Error deleting medication:", error);
      res.status(500).json({ message: "Failed to delete medication" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
