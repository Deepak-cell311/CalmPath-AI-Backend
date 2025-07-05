CREATE TYPE "public"."care_level" AS ENUM('low', 'medium', 'high');--> statement-breakpoint
CREATE TYPE "public"."role" AS ENUM('admin', 'caregiver', 'patient', 'family');--> statement-breakpoint
ALTER TABLE "patients" ALTER COLUMN "care_level" SET DATA TYPE "public"."care_level" USING "care_level"::"public"."care_level";--> statement-breakpoint
ALTER TABLE "patients" ALTER COLUMN "care_level" DROP DEFAULT;--> statement-breakpoint
ALTER TABLE "users" ALTER COLUMN "account_type" SET DEFAULT 'Patient';--> statement-breakpoint
ALTER TABLE "users" ALTER COLUMN "role" SET DATA TYPE "public"."role" USING "role"::"public"."role";--> statement-breakpoint
ALTER TABLE "users" ALTER COLUMN "role" DROP DEFAULT;--> statement-breakpoint
ALTER TABLE "users" ALTER COLUMN "care_level" SET DATA TYPE "public"."care_level" USING "care_level"::"public"."care_level";--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "phone_number" varchar(10);--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "password_hash" text NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_phone_number_unique" UNIQUE("phone_number");