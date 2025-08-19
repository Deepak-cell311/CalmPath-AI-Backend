import { pgTable, pgEnum, text, serial, timestamp, integer, varchar, index, jsonb, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z, ZodType } from "zod";

export const roleEnum = pgEnum('role', ['admin', 'caregiver', 'patient', 'family']);
export type Role = 'admin' | 'caregiver' | 'patient' | 'family';

export const careLevelEnum = pgEnum('care_level', ['low', 'medium', 'high']);
export type CareLevel = 'low' | 'medium' | 'high';

export const sessions = pgTable("sessions", {
    id: serial("id").primaryKey(),
    startTime: timestamp("start_time").defaultNow().notNull(),
    endTime: timestamp("end_time"),
    duration: text("duration"),
    interactionCount: integer("interaction_count").notNull().default(0),
    calmingScore: integer("calming_score").notNull().default(0),
});

export const memoryPhotos = pgTable("memory_photos", {
  id: serial("id").primaryKey(),
  // Owner of the uploaded photo (family member user ID)
  uploadedBy: varchar("uploaded_by", { length: 255 }).references(() => users.id),
  photoname: varchar("photoname", { length: 255 }).notNull(),
  description: text("description"),
  contextAndStory: text("context_and_story"),
  file: varchar("file", { length: 500 }).notNull(), // URL to the uploaded image
  tags: jsonb("tags").$type<string[]>().notNull().default([]),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

export const conversations = pgTable("conversations", {
    id: serial("id").primaryKey(),
    sessionId: integer("session_id").references(() => sessions.id),
    patientId: integer("patient_id").references(() => patients.id),
    staffId: varchar("staff_id").references(() => users.id),
    userMessage: text("user_message").notNull(),
    transcript: text("transcript"),
    duration: integer("duration"), // in seconds
    sentiment: varchar("sentiment", { length: 20 }),
    aiResponse: text("ai_response").notNull(),
    intent: text("intent"),
    redirectionType: text("redirection_type"),
    timestamp: timestamp("timestamp").defaultNow().notNull(),
});

export const emergencyEvents = pgTable("emergency_events", {
    id: serial("id").primaryKey(),
    sessionId: integer("session_id").references(() => sessions.id),
    eventType: text("event_type").notNull(),
    description: text("description"),
    timestamp: timestamp("timestamp").defaultNow().notNull(),
});

// Session storage table for Replit Auth
export const authSessions = pgTable(
    "auth_sessions",
    {
        sid: varchar("sid").primaryKey(),
        sess: jsonb("sess").notNull(),
        expire: timestamp("expire").notNull(),
    },
    (table) => [index("IDX_session_expire").on(table.expire)],
);

// User storage table for authentication and billing
export const users = pgTable("users", {
    id: varchar("id").primaryKey().notNull(),
    email: varchar("email").unique(),
    firstName: varchar("first_name"),
    lastName: varchar("last_name"),
    profileImageUrl: varchar("profile_image_url"),
    phoneNumber: varchar("phone_number", { length: 10 }).unique(),
    accountType: varchar("account_type", { enum: ["Patient", "Family Member", "Facility Staff"] }).default("Patient"),
    facilityId: varchar("facility_id").references(() => facilities.id),
    role: roleEnum().default('patient'),
    passwordHash: text("password_hash").notNull(),
    stripeCustomerId: varchar("stripe_customer_id"),
    stripeSubscriptionId: varchar("stripe_subscription_id"),
    subscriptionStatus: varchar("subscription_status").default("inactive"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),

    // 👇 Add patient-specific fields here
    status: varchar("status", { length: 20 }),
    roomNumber: varchar("room_number"),
    care_level: careLevelEnum().default('low'),
    medicalNotes: text("medical_notes"),
    lastInteraction: timestamp("last_interaction"),
    admissionDate: timestamp("admission_date"),
    emergencyContact: varchar("emergency_contact"),
    emergencyPhone: varchar("emergency_phone"),
    isActive: boolean("is_active"),
    userId: varchar("user_id"),
    relationToPatient: varchar("relation_to_patient"), // for family members
    patientAccessCode: varchar("patient_access_code"), // for family members
    facilityStaffFacilityId: varchar("facility_staff_facility_id").references(() => facilities.id), // for facility staff
    usedInviteCode: boolean("used_invite_code").default(false), // Track if user used an invite code
});


export const facilities = pgTable("facilities", {
    id: varchar("id").primaryKey().notNull(),
    name: varchar("name").notNull(),
    address: text("address"),
    phone: varchar("phone"),
    adminEmail: varchar("admin_email"),
    subscriptionTier: varchar("subscription_tier", { enum: ["basic", "premium", "enterprise"] }).default("basic"),
    monthlyPrice: varchar("monthly_price"), // Store the actual monthly price
    maxPatients: integer("max_patients").default(10),
    isActive: boolean("is_active").default(true),
    promoCode: varchar("promo_code"),
    stripeProductId: varchar("stripe_product_id"),
    stripePriceId: varchar("stripe_price_id"),
    stripeCouponId: varchar("stripe_coupon_id"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
    tagline: varchar("tagline", { length: 255 }),
    logoUrl: varchar("logo_url", { length: 255 }),
    brandColor: varchar("brand_color", { length: 16 }),
});

export const patients = pgTable("patients", {
    id: serial("id").primaryKey(),
    facilityId: varchar("facility_id").references(() => facilities.id),
    userId: varchar("user_id").references(() => users.id), // For individual accounts
    firstName: varchar("first_name").notNull(),
    lastName: varchar("last_name").notNull(),
    age: integer("age").default(0), // Default to 0 if not provided
    status: varchar("status", { length: 20 }).notNull().default("ok"),
    roomNumber: varchar("room_number"),
    care_level: careLevelEnum().default('low'),
    medicalNotes: text("medical_notes"),
    lastInteraction: timestamp("last_interaction").defaultNow(),
    profileImageUrl: varchar("profile_image_url"),
    admissionDate: timestamp("admission_date").defaultNow(),
    emergencyContact: varchar("emergency_contact"),
    emergencyPhone: varchar("emergency_phone"),
    isActive: boolean("is_active").default(true),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
});

// Link sessions to users for billing and access control
export const userSessions = pgTable("user_sessions", {
    id: serial("id").primaryKey(),
    userId: varchar("user_id").references(() => users.id).notNull(),
    patientId: integer("patient_id").references(() => patients.id),
    sessionId: integer("session_id").references(() => sessions.id).notNull(),
    timestamp: timestamp("timestamp").defaultNow().notNull(),
});

export const insertSessionSchema = createInsertSchema(sessions).omit({
    id: true,
    startTime: true,
});

export const insertConversationSchema = createInsertSchema(conversations).omit({
    id: true,
    timestamp: true,
});

export const insertEmergencyEventSchema = createInsertSchema(emergencyEvents).omit({
    id: true,
    timestamp: true,
});





//======================================= Dashboard Schema =======================================//


export const staffNotes = pgTable("staff_notes", {
    id: serial("id").primaryKey(),
    patientId: integer("patient_id").notNull().references(() => patients.id),
    staffId: varchar("staff_id").notNull().references(() => users.id),
    content: text("content").notNull(),
    createdAt: timestamp("created_at").defaultNow(),
});

export const moodLogs = pgTable("mood_logs", {
    id: serial("id").primaryKey(),
    patientId: integer("patient_id").notNull().references(() => patients.id),
    status: varchar("status", { length: 20 }).notNull(), // anxious, ok, good
    loggedBy: varchar("logged_by"), // system or staff_id
    notes: text("notes"),
    createdAt: timestamp("created_at").defaultNow(),
});


export const therapeuticPhotos = pgTable("therapeutic_photos", {
    id: serial("id").primaryKey(),
    patientId: integer("patient_id").notNull().references(() => patients.id),
    staffId: varchar("staff_id").references(() => users.id),
    url: varchar("url", { length: 500 }).notNull(),
    transcript: text("transcript"),
    description: text("description"),
    duration: integer("duration"), // in seconds
    sentiment: varchar("sentiment", { length: 20 }),
    category: varchar("category", { length: 50 }), // family, nature, pets, etc.
    uploadedBy: varchar("uploaded_by").references(() => users.id),
    createdAt: timestamp("created_at").defaultNow(),
});

export const alerts = pgTable("alerts", {
    id: serial("id").primaryKey(),
    patientId: integer("patient_id").notNull().references(() => patients.id),
    type: varchar("type", { length: 50 }).notNull(), // status_change, no_activity
    message: text("message").notNull(),
    isRead: boolean("is_read").default(false),
    createdAt: timestamp("created_at").defaultNow(),
});

export const medications = pgTable("medications", {
  id: serial("id").primaryKey(),
  patientId: integer("patient_id").notNull().references(() => patients.id),
  name: varchar("name", { length: 255 }).notNull(),
  dosage: varchar("dosage", { length: 100 }),
  frequency: varchar("frequency", { length: 100 }),
  time: varchar("time", { length: 100 }),
  createdAt: timestamp("created_at").defaultNow(),
});

export const reminders = pgTable("reminders", {
  id: serial("id").primaryKey(),
  patientId: integer("patient_id").notNull().references(() => patients.id),
  createdBy: varchar("created_by"), // family member who created the reminder - made nullable to fix FK constraint
  message: text("message").notNull(),
  scheduledTime: timestamp("scheduled_time").notNull(),
  isActive: boolean("is_active").default(true),
  isCompleted: boolean("is_completed").default(false),
  completedAt: timestamp("completed_at"),
  createdAt: timestamp("created_at").defaultNow(), // FIXED
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Flat Payment Invite System Tables
export const facilityInvitePackages = pgTable("facility_invite_packages", {
  id: serial("id").primaryKey(),
  facilityId: varchar("facility_id").notNull().references(() => facilities.id),
  packageName: varchar("package_name", { length: 100 }).notNull(), // e.g. "10 Invites Package"
  inviteCount: integer("invite_count").notNull(), // Number of invites in this package
  priceInCents: integer("price_in_cents").notNull(), // Price in cents (e.g. 10000 for $100)
  stripePriceId: varchar("stripe_price_id"), // Stripe price ID for this package
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const facilityInvitePurchases = pgTable("facility_invite_purchases", {
  id: serial("id").primaryKey(),
  facilityId: varchar("facility_id").notNull().references(() => facilities.id),
  packageId: integer("package_id").notNull().references(() => facilityInvitePackages.id),
  stripeSessionId: varchar("stripe_session_id"), // Stripe checkout session ID
  stripePaymentIntentId: varchar("stripe_payment_intent_id"), // Stripe payment intent ID
  totalPaidInCents: integer("total_paid_in_cents").notNull(),
  inviteCount: integer("invite_count").notNull(), // Number of invites purchased
  status: varchar("status", { enum: ["pending", "completed", "failed", "refunded"] }).default("pending"),
  purchasedAt: timestamp("purchased_at").defaultNow(),
  completedAt: timestamp("completed_at"),
});

export const facilityInvites = pgTable("facility_invites", {
  id: serial("id").primaryKey(),
  facilityId: varchar("facility_id").notNull().references(() => facilities.id),
  purchaseId: integer("purchase_id").notNull().references(() => facilityInvitePurchases.id),
  inviteCode: varchar("invite_code", { length: 20 }).notNull().unique(), // Unique invite code
  invitedEmail: varchar("invited_email"), // Email of the invited person
  invitedPhone: varchar("invited_phone"), // Phone of the invited person
  invitedName: varchar("invited_name", { length: 100 }), // Name of the invited person
  status: varchar("status", { enum: ["unused", "used", "expired"] }).default("unused"),
  usedByUserId: varchar("used_by_user_id").references(() => users.id), // Who used this invite
  usedAt: timestamp("used_at"), // When the invite was used
  expiresAt: timestamp("expires_at"), // When the invite expires
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Insert schemas
export const insertPatientSchema = createInsertSchema(patients).omit({
    id: true,
    createdAt: true,
    updatedAt: true,
});

export const insertStaffNoteSchema = createInsertSchema(staffNotes).omit({
    id: true,
    createdAt: true,
});

export const insertMoodLogSchema = createInsertSchema(moodLogs).omit({
    id: true,
    createdAt: true,
});


export const insertTherapeuticPhotoSchema = createInsertSchema(therapeuticPhotos).omit({
    id: true,
    createdAt: true,
});

export const insertAlertSchema = createInsertSchema(alerts).omit({
    id: true,
    createdAt: true,
});

export const insertMedicationSchema = createInsertSchema(medications).omit({
  id: true,
  createdAt: true,
});

export const insertReminderSchema = createInsertSchema(reminders).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

// Invite system insert schemas
export const insertFacilityInvitePackageSchema = createInsertSchema(facilityInvitePackages).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertFacilityInvitePurchaseSchema = createInsertSchema(facilityInvitePurchases).omit({
  id: true,
  purchasedAt: true,
  completedAt: true,
});

export const insertFacilityInviteSchema = createInsertSchema(facilityInvites).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type StaffNote = typeof staffNotes.$inferSelect;
export type InsertStaffNote = z.infer<(typeof insertStaffNoteSchema) & ZodType<any, any, any>>;
export type MoodLog = typeof moodLogs.$inferSelect;
export type InsertMoodLog = z.infer<(typeof insertMoodLogSchema) & ZodType<any, any, any>>;
export type TherapeuticPhoto = typeof therapeuticPhotos.$inferSelect;
export type InsertTherapeuticPhoto = z.infer<(typeof insertTherapeuticPhotoSchema) & ZodType<any, any, any>>;
export type Alert = typeof alerts.$inferSelect;
export type InsertAlert = z.infer<(typeof insertAlertSchema) & ZodType<any, any, any>>;
export type Medication = typeof medications.$inferSelect;
export type InsertMedication = z.infer<(typeof insertMedicationSchema) & ZodType<any, any, any>>;
export type Reminder = typeof reminders.$inferSelect;
export type InsertReminder = z.infer<(typeof insertReminderSchema) & ZodType<any, any, any>>;

export type Session = typeof sessions.$inferSelect;
export type InsertSession = z.infer<(typeof insertSessionSchema) & ZodType<any, any, any>>;
export type Conversation = typeof conversations.$inferSelect;
export type InsertConversation = z.infer<(typeof insertConversationSchema) & ZodType<any, any, any>>;
export type EmergencyEvent = typeof emergencyEvents.$inferSelect;
export type InsertEmergencyEvent = z.infer<(typeof insertEmergencyEventSchema) & ZodType<any, any, any>>;

// User and billing types
export type User = typeof users.$inferSelect;
export type UpsertUser = typeof users.$inferInsert;
export type UserSession = typeof userSessions.$inferSelect;
export type InsertUserSession = typeof userSessions.$inferInsert;
export type Facility = typeof facilities.$inferSelect;
export type InsertFacility = typeof facilities.$inferInsert;
export type Patient = typeof patients.$inferSelect;
export type InsertPatient = z.infer<(typeof insertPatientSchema) & ZodType<any, any, any>>;

// Invite System Types
export type FacilityInvitePackage = typeof facilityInvitePackages.$inferSelect;
export type InsertFacilityInvitePackage = typeof facilityInvitePackages.$inferInsert;
export type FacilityInvitePurchase = typeof facilityInvitePurchases.$inferSelect;
export type InsertFacilityInvitePurchase = typeof facilityInvitePurchases.$inferInsert;
export type FacilityInvite = typeof facilityInvites.$inferSelect;
export type InsertFacilityInvite = typeof facilityInvites.$inferInsert;