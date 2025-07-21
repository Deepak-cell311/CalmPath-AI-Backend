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
} from "../shared/schema";
import { db } from "./db";
import { eq, desc, sql } from "drizzle-orm";
import { alias } from 'drizzle-orm/pg-core';

// Interface for storage operations
export interface IStorage {
  // User operations
  getUser(id: string): Promise<User | undefined>;
  upsertUser(user: UpsertUser): Promise<User>;

  // Patient operations
  getAllPatients(): Promise<Patient[]>;
  getPatient(id: number): Promise<Patient | undefined>;
  createPatient(data: InsertPatient): Promise<Patient>;
  updatePatientStatus(id: number, status: string): Promise<Patient>;
  updatePatientInteraction(id: number): Promise<Patient>;
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
}

export class DatabaseStorage implements IStorage {
  // User operations
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
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
  async getAllPatients(): Promise<Patient[]> {
    return db.select().from(patients).orderBy(desc(patients.lastInteraction));
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
}

export const storage = new DatabaseStorage(); 