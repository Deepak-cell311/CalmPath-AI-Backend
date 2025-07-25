import type { Config } from "drizzle-kit";
import * as dotenv from "dotenv";
dotenv.config();

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL, ensure the database is provisioned");
}


export default {
  schema: "./shared/schema.ts",
  out: "./migrations",
  dialect: 'postgresql',
  // driver: "neon",
  dbCredentials: {
    url: process.env.DATABASE_URL!,
  },
} satisfies Config; 