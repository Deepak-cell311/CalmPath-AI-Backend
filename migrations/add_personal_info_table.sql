-- Add personal_info table for storing patient personal information
CREATE TABLE IF NOT EXISTS "personal_info" (
    "id" serial PRIMARY KEY,
    "patient_id" integer NOT NULL REFERENCES "patients"("id"),
    "work" text,
    "family" text,
    "hobbies" text,
    "food" text,
    "other" text,
    "created_by" varchar REFERENCES "users"("id"),
    "created_at" timestamp DEFAULT now(),
    "updated_at" timestamp DEFAULT now()
);

-- Add index for faster lookups by patient_id
CREATE INDEX IF NOT EXISTS idx_personal_info_patient_id ON "personal_info"("patient_id");
