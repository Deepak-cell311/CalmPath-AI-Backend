import {
  users,
  type User,
  type UpsertUser,
  patients,
  type Patient,
  type InsertPatient,
  staffNotes,
  type InsertStaffNote,
  type StaffNote,
  moodLogs,
  type InsertMoodLog,
  type MoodLog,
  conversations,
  type InsertConversation,
  type Conversation,
  therapeuticPhotos,
  type InsertTherapeuticPhoto,
  type TherapeuticPhoto,
  alerts,
  type InsertAlert,
  type Alert,
  medications,
  type Medication,
  type InsertMedication,
  facilities,
  type Facility,
  reminders,
  type Reminder,
  type InsertReminder,
  facilityInvitePackages,
  type FacilityInvitePackage,
  type InsertFacilityInvitePackage,
  facilityInvitePurchases,
  type FacilityInvitePurchase,
  type InsertFacilityInvitePurchase,
  facilityInvites,
  type FacilityInvite,
  type InsertFacilityInvite,
} from "../shared/schema";
import { db } from "./db";
import { eq, desc, sql, and } from "drizzle-orm";
import { alias } from 'drizzle-orm/pg-core';

// Interface for storage operations
export interface IStorage {
  // User operations
  getUser(id: string): Promise<User | undefined>;
  upsertUser(user: UpsertUser): Promise<User>;

  // Patient operations
  getAllPatients(filters?: { userId?: string; facilityId?: string }): Promise<Patient[]>;
  getPatient(id: number): Promise<Patient | undefined>;
  createPatient(data: InsertPatient): Promise<Patient>;
  updatePatientStatus(id: number, status: string): Promise<Patient>;
  updatePatientInteraction(id: number): Promise<Patient>;
  deletePatient(id: number): Promise<boolean>;
  getPatientNotes(patientId: number): Promise<StaffNote[]>;
  createStaffNote(data: InsertStaffNote): Promise<StaffNote>;
  getPatientMoodHistory(patientId: number, days: number): Promise<MoodLog[]>;
  getPatientPhotos(patientId: number): Promise<TherapeuticPhoto[]>;
  createConversation(data: InsertConversation): Promise<Conversation>;
  createTherapeuticPhoto(data: InsertTherapeuticPhoto): Promise<TherapeuticPhoto>;
  deleteTherapeuticPhoto(id: number): Promise<void>;
  getUnreadAlerts(): Promise<Alert[]>;
  markAlertAsRead(id: number): Promise<void>;
  getPatientStatusCounts(): Promise<{ status: string; count: number }[]>;
  getPatientsWithNoRecentActivity(hours: number): Promise<Patient[]>;
  createAlert(data: InsertAlert): Promise<Alert>;
  createMoodLog(data: InsertMoodLog): Promise<MoodLog>;
  getMedications(patientId: number): Promise<Medication[]>;
  createMedication(data: InsertMedication): Promise<Medication>;
  deleteMedication(id: number): Promise<void>;
  
  // Reminder operations
  getPatientReminders(patientId: number): Promise<Reminder[]>;
  createReminder(data: InsertReminder): Promise<Reminder>;
  updateReminder(id: number, data: Partial<Reminder>): Promise<Reminder>;
  deleteReminder(id: number): Promise<void>;
  getActiveRemindersForPatient(patientId: number): Promise<Reminder[]>;
  markReminderAsCompleted(id: number): Promise<void>;
  
  // Stripe-related methods
  updateUserStripeCustomerId(userId: string, stripeCustomerId: string): Promise<void>;
  updateUserStripeSubscriptionId(userId: string, stripeSubscriptionId: string): Promise<void>;
  updateUserSubscriptionStatus(userId: string, status: string): Promise<void>;
  
  // Facility management methods
  getAllFacilities(): Promise<Facility[]>;
  createFacility(data: Partial<Facility>): Promise<Facility>;
  updateFacility(data: Partial<Facility>): Promise<Facility>;
  
  // Invite system methods
  getFacilityInvitePackages(facilityId: string): Promise<FacilityInvitePackage[]>;
  getFacilityInvitePackage(packageId: number): Promise<FacilityInvitePackage | undefined>;
  createFacilityInvitePackage(data: InsertFacilityInvitePackage): Promise<FacilityInvitePackage>;
  getFacilityInvitePurchases(facilityId: string): Promise<FacilityInvitePurchase[]>;
  createFacilityInvitePurchase(data: InsertFacilityInvitePurchase): Promise<FacilityInvitePurchase>;
  getFacilityAvailableInvites(facilityId: string): Promise<FacilityInvite[]>;
  createFacilityInvites(facilityId: string, purchaseId: number, inviteCount: number): Promise<FacilityInvite[]>;
  useFacilityInvite(inviteCode: string, facilityId: string, userInfo: { email?: string; phone?: string; name?: string }): Promise<{ success: boolean; message?: string; facility?: Facility; user?: User; patient?: Patient }>;
}

export class DatabaseStorage implements IStorage {
  // User operations
  async getUser(id: string): Promise<User | undefined> {
    console.log("Storage: Getting user with ID:", id, "type:", typeof id);
    
    // Debug: Check what users exist in the database
    const allUsers = await db.select().from(users);
    console.log("Storage: All users in database:", allUsers.map(u => ({ id: u.id, email: u.email })));
    
    const [user] = await db.select().from(users).where(eq(users.id, id));
    console.log("Storage: User lookup result:", user ? { id: user.id, email: user.email } : "not found");
    return user;
  }

  async upsertUser(userData: UpsertUser): Promise<User> {
    const [user] = await db
      .insert(users)
      .values(userData)
      .onConflictDoUpdate({
        target: users.id,
        set: {
          ...userData,
          updatedAt: new Date(),
        },
      })
      .returning();
    return user;
  }

  // Patient operations
  async getAllPatients(filters?: { userId?: string; facilityId?: string }): Promise<Patient[]> {
    return db
      .select()
      .from(patients)
      .where(
        and(
          filters?.userId ? eq(patients.userId, filters.userId) : undefined,
          filters?.facilityId ? eq(patients.facilityId, filters.facilityId) : undefined,
        )
      )
      .orderBy(desc(patients.lastInteraction));
  }

  async getPatient(id: number): Promise<Patient | undefined> {
    const [patient] = await db.select().from(patients).where(eq(patients.id, id));
    return patient;
  }

  async createPatient(data: InsertPatient): Promise<Patient> {
    const [patient] = await db.insert(patients).values(data).returning();
    return patient;
  }

  async updatePatientStatus(id: number, status: string): Promise<Patient> {
    const [patient] = await db
      .update(patients)
      .set({ status, updatedAt: new Date() })
      .where(eq(patients.id, id))
      .returning();
    return patient;
  }

  async updatePatientInteraction(id: number): Promise<Patient> {
    const [patient] = await db
      .update(patients)
      .set({ lastInteraction: new Date() })
      .where(eq(patients.id, id))
      .returning();
    return patient;
  }

  async deletePatient(id: number): Promise<boolean> {
    const result = await db.delete(patients).where(eq(patients.id, id));
    return result.rowCount ? result.rowCount > 0 : false;
  }

  async getPatientNotes(patientId: number): Promise<StaffNote[]> {
    return db.select().from(staffNotes).where(eq(staffNotes.patientId, patientId)).orderBy(desc(staffNotes.createdAt));
  }

  async createStaffNote(data: InsertStaffNote): Promise<StaffNote> {
    const [note] = await db.insert(staffNotes).values(data).returning();
    return note;
  }

  async getPatientMoodHistory(patientId: number, days: number): Promise<MoodLog[]> {
     // ✅ Sanitize days to avoid SQL injection
  const safeDays = Math.max(1, Math.min(days, 30));
    return db.select().from(moodLogs).where(sql`"patient_id" = ${patientId} AND "created_at" >= NOW() - INTERVAL ${sql.raw(`'${safeDays} days'`)}`).orderBy(desc(moodLogs.createdAt));
  }

  async getPatientPhotos(patientId: number): Promise<TherapeuticPhoto[]> {
    return db.select().from(therapeuticPhotos).where(eq(therapeuticPhotos.patientId, patientId)).orderBy(desc(therapeuticPhotos.createdAt));
  }

  async createConversation(data: InsertConversation): Promise<Conversation> {
    const [conversation] = await db.insert(conversations).values(data).returning();
    return conversation;
  }

  async createTherapeuticPhoto(data: InsertTherapeuticPhoto): Promise<TherapeuticPhoto> {
    const [photo] = await db.insert(therapeuticPhotos).values(data).returning();
    return photo;
  }

  async deleteTherapeuticPhoto(id: number): Promise<void> {
    await db.delete(therapeuticPhotos).where(eq(therapeuticPhotos.id, id));
  }

  async getUnreadAlerts(): Promise<Alert[]> {
      const patient = alias(patients, 'patient');
      const alertWithPatient = await db
          .select({
              alert: alerts,
              patientName: patient.firstName,
          })
          .from(alerts)
          .leftJoin(patient, eq(alerts.patientId, patient.id))
          .where(eq(alerts.isRead, false))
          .orderBy(desc(alerts.createdAt));

      return alertWithPatient.map(ap => ({
          ...ap.alert,
          message: `${ap.patientName} ${ap.alert.message}`
      }));
  }

  async markAlertAsRead(id: number): Promise<void> {
    await db.update(alerts).set({ isRead: true }).where(eq(alerts.id, id));
  }

  async getPatientStatusCounts(): Promise<{ status: string; count: number }[]> {
    const result: { status: string, count: number }[] = await db.select({
      status: patients.status,
      count: sql<number>`count(*)::int`
    }).from(patients).groupBy(patients.status);
    return result;
  }

  async getPatientsWithNoRecentActivity(hours: number): Promise<Patient[]> {
    return db.select().from(patients).where(sql`"last_interaction" < NOW() - INTERVAL '${hours} hours'`);
  }

  async createAlert(data: InsertAlert): Promise<Alert> {
    const [alert] = await db.insert(alerts).values(data).returning();
    return alert;
  }

  async createMoodLog(data: InsertMoodLog): Promise<MoodLog> {
      const [log] = await db.insert(moodLogs).values(data).returning();
      return log;
  }

  async getMedications(patientId: number): Promise<Medication[]> {
    return db.select().from(medications).where(eq(medications.patientId, patientId));
  }

  async createMedication(data: InsertMedication): Promise<Medication> {
    const [med] = await db.insert(medications).values(data).returning();
    return med;
  }

  async deleteMedication(id: number): Promise<void> {
    await db.delete(medications).where(eq(medications.id, id));
  }

  // Reminder operations
  async getPatientReminders(patientId: number): Promise<Reminder[]> {
    return db.select().from(reminders).where(eq(reminders.patientId, patientId));
  }

  async createReminder(data: InsertReminder): Promise<Reminder> {
    const [reminder] = await db.insert(reminders).values(data).returning();
    return reminder;
  }

  async updateReminder(id: number, data: Partial<Reminder>): Promise<Reminder> {
    const [reminder] = await db
      .update(reminders)
      .set(data)
      .where(eq(reminders.id, id))
      .returning();
    return reminder;
  }

  async deleteReminder(id: number): Promise<void> {
    await db.delete(reminders).where(eq(reminders.id, id));
  }

  async getActiveRemindersForPatient(patientId: number): Promise<Reminder[]> {
    return db.select().from(reminders).where(and(eq(reminders.patientId, patientId), eq(reminders.isCompleted, false)));
  }

  async markReminderAsCompleted(id: number): Promise<void> {
    await db.update(reminders).set({ isCompleted: true }).where(eq(reminders.id, id));
  }

  // Stripe-related methods
  async updateUserStripeCustomerId(userId: string, stripeCustomerId: string): Promise<void> {
    await db.update(users)
      .set({ 
        stripeCustomerId: stripeCustomerId,
        updatedAt: new Date()
      })
      .where(eq(users.id, userId));
  }

  async updateUserStripeSubscriptionId(userId: string, stripeSubscriptionId: string): Promise<void> {
    await db.update(users)
      .set({ 
        stripeSubscriptionId: stripeSubscriptionId,
        updatedAt: new Date()
      })
      .where(eq(users.id, userId));
  }

  async updateUserSubscriptionStatus(userId: string, status: string): Promise<void> {
    await db.update(users)
      .set({ 
        updatedAt: new Date()
      })
      .where(eq(users.id, userId));
  }

  // Facility management methods
  async getAllFacilities(): Promise<Facility[]> {
    return db.select().from(facilities);
  }

  async createFacility(data: Partial<Facility>): Promise<Facility> {
    // Generate a unique facility ID if not provided
    const facilityId = data.id || `facility_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const [facility] = await db.insert(facilities).values({
      ...data,
      id: facilityId
    } as Facility).returning();
    return facility;
  }

  async updateFacility(data: Partial<Facility>): Promise<Facility> {
    const [facility] = await db
      .update(facilities)
      .set(data)
      .where(eq(facilities.id, data.id || ""))
      .returning();
    return facility;
  }

  // Invite system methods
  async getFacilityInvitePackages(facilityId: string): Promise<FacilityInvitePackage[]> {
    return db.select().from(facilityInvitePackages).where(eq(facilityInvitePackages.facilityId, facilityId));
  }

  async getFacilityInvitePackage(packageId: number): Promise<FacilityInvitePackage | undefined> {
    const [pkg] = await db.select().from(facilityInvitePackages).where(eq(facilityInvitePackages.id, packageId));
    return pkg;
  }

  async createFacilityInvitePackage(data: InsertFacilityInvitePackage): Promise<FacilityInvitePackage> {
    const [pkg] = await db.insert(facilityInvitePackages).values(data).returning();
    return pkg;
  }

  async getFacilityInvitePurchases(facilityId: string): Promise<FacilityInvitePurchase[]> {
    return db.select().from(facilityInvitePurchases).where(eq(facilityInvitePurchases.facilityId, facilityId));
  }

  async createFacilityInvitePurchase(data: InsertFacilityInvitePurchase): Promise<FacilityInvitePurchase> {
    const [purchase] = await db.insert(facilityInvitePurchases).values(data).returning();
    return purchase;
  }

  async getFacilityAvailableInvites(facilityId: string): Promise<FacilityInvite[]> {
    return db.select().from(facilityInvites).where(and(
      eq(facilityInvites.facilityId, facilityId),
      eq(facilityInvites.status, 'unused')
    ));
  }

  async createFacilityInvites(facilityId: string, purchaseId: number, inviteCount: number): Promise<FacilityInvite[]> {
    const invites: InsertFacilityInvite[] = [];
    
    for (let i = 0; i < inviteCount; i++) {
      // Generate unique invite code
      const inviteCode = this.generateInviteCode();
      
      invites.push({
        facilityId,
        purchaseId,
        inviteCode,
        status: 'unused',
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year expiry
      });
    }

    const createdInvites = await db.insert(facilityInvites).values(invites).returning();
    return createdInvites;
  }

  async useFacilityInvite(inviteCode: string, facilityId: string, userInfo: { email?: string; phone?: string; name?: string }): Promise<{ success: boolean; message?: string; facility?: Facility; user?: User }> {
    try {
      // Find the invite
      const [invite] = await db.select().from(facilityInvites).where(eq(facilityInvites.inviteCode, inviteCode));
      
      if (!invite) {
        return { success: false, message: "Invalid invite code" };
      }

      if (invite.status !== 'unused') {
        return { success: false, message: "Invite code has already been used" };
      }

      if (invite.expiresAt && new Date() > invite.expiresAt) {
        return { success: false, message: "Invite code has expired" };
      }

      if (invite.facilityId !== facilityId) {
        return { success: false, message: "Invite code is not valid for this facility" };
      }

      // Get the facility
      const [facility] = await db.select().from(facilities).where(eq(facilities.id, facilityId));
      if (!facility) {
        return { success: false, message: "Facility not found" };
      }

      // Create or get user
      let user: User;
      const userId = `invite_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      
      if (userInfo.email) {
        // Try to find existing user by email
        const [existingUser] = await db.select().from(users).where(eq(users.email, userInfo.email));
        if (existingUser) {
          user = existingUser;
        } else {
          // Create new user
          const [newUser] = await db.insert(users).values({
            id: userId,
            email: userInfo.email,
            firstName: userInfo.name?.split(' ')[0] || 'Invited',
            lastName: userInfo.name?.split(' ').slice(1).join(' ') || 'User',
            phoneNumber: userInfo.phone || '',
            accountType: 'Patient',
            role: 'patient',
            passwordHash: 'invite_user', // Will need to be set properly when they sign up
            isActive: true,
          }).returning();
          user = newUser;
        }
      } else if (userInfo.phone) {
        // Try to find existing user by phone
        const [existingUser] = await db.select().from(users).where(eq(users.phoneNumber, userInfo.phone));
        if (existingUser) {
          user = existingUser;
        } else {
          // Create new user
          const [newUser] = await db.insert(users).values({
            id: userId,
            phoneNumber: userInfo.phone,
            firstName: userInfo.name?.split(' ')[0] || 'Invited',
            lastName: userInfo.name?.split(' ').slice(1).join(' ') || 'User',
            accountType: 'Patient',
            role: 'patient',
            passwordHash: 'invite_user', // Will need to be set properly when they sign up
            isActive: true,
          }).returning();
          user = newUser;
        }
      } else {
        return { success: false, message: "Email or phone number is required" };
      }

      // Update user to link to facility
      await db.update(users)
        .set({
          facilityId: facilityId,
          updatedAt: new Date(),
        })
        .where(eq(users.id, user.id));

      // Check if patient record already exists for this user
      const [existingPatient] = await db.select().from(patients).where(eq(patients.userId, user.id));
      
      let patient: Patient;
      if (existingPatient) {
        // Update existing patient record to link to facility
        const [updatedPatient] = await db.update(patients)
          .set({
            facilityId: facilityId,
            updatedAt: new Date(),
          })
          .where(eq(patients.userId, user.id))
          .returning();
        patient = updatedPatient;
      } else {
        // Create new patient record
        const [newPatient] = await db.insert(patients).values({
          facilityId: facilityId,
          userId: user.id,
          firstName: user.firstName || userInfo.name?.split(' ')[0] || 'Invited',
          lastName: user.lastName || userInfo.name?.split(' ').slice(1).join(' ') || 'User',
          status: 'ok',
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        }).returning();
        patient = newPatient;
      }

      // Mark invite as used
      await db.update(facilityInvites)
        .set({
          status: 'used',
          usedByUserId: user.id,
          usedAt: new Date(),
          invitedEmail: userInfo.email,
          invitedPhone: userInfo.phone,
          invitedName: userInfo.name,
        })
        .where(eq(facilityInvites.id, invite.id));

      return { success: true, facility, user };
    } catch (error) {
      console.error("Error using invite:", error);
      return { success: false, message: "Failed to use invite" };
    }
  }

  private generateInviteCode(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < 8; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }
}

export const storage = new DatabaseStorage(); 