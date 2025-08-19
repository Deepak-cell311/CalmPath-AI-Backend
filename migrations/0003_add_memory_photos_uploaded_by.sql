-- Add owner column to scope memory photos to uploader
ALTER TABLE "memory_photos"
ADD COLUMN IF NOT EXISTS "uploaded_by" varchar(255);

-- Optional: add FK to users table (will be set NULL on delete)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'memory_photos_uploaded_by_users_id_fk'
  ) THEN
    ALTER TABLE "memory_photos"
    ADD CONSTRAINT "memory_photos_uploaded_by_users_id_fk"
    FOREIGN KEY ("uploaded_by") REFERENCES "public"."users"("id")
    ON DELETE SET NULL ON UPDATE NO ACTION;
  END IF;
END $$;

-- Optional: index for faster owner lookups
CREATE INDEX IF NOT EXISTS idx_memory_photos_uploaded_by ON "memory_photos"("uploaded_by");