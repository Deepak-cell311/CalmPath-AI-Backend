import { db } from './db'; // adjust path as needed
import { CareLevel, Role, users as usersTable } from '../shared/schema'; // adjust import as per your schema
import { eq } from 'drizzle-orm';
import { User } from "../shared/schema";
export { User };

// Get user by email from DB
export const getUserByEmail = async (email: string): Promise<User | undefined> => {
  const result = await db.select().from(usersTable).where(eq(usersTable.email, email));
  return result[0];
};

// Create user in DB
export const createUser = async (
  email: string,
  name: string,
  accountType: 'Patient' | 'Family Member' | 'Facility Staff',
  passwordHash: string
): Promise<User> => {
  const newUser = {
    id: crypto.randomUUID(),
    email,
    firstName: name,
    lastName: '',
    profileImageUrl: '',
    accountType,
    facilityId: null,
    role: "patient" as Role,
    stripeCustomerId: null,
    stripeSubscriptionId: null,
    subscriptionStatus: 'inactive',
    createdAt: new Date(),
    updatedAt: new Date(),
    age: 0,
    status: '',
    roomNumber: '',
    careLevel: 'low' as CareLevel,
    medicalNotes: '',
    lastInteraction: new Date(),
    admissionDate: new Date(),
    emergencyContact: '',
    emergencyPhone: '',
    isActive: true,
    userId: null,
    passwordHash, // <-- required by schema
    // phoneNumber
  };
  const inserted = await db.insert(usersTable).values(newUser).returning();
  return inserted[0];
};