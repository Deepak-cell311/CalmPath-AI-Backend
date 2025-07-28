CREATE TABLE "medications" (
	"id" serial PRIMARY KEY NOT NULL,
	"patient_id" integer NOT NULL,
	"name" varchar(255) NOT NULL,
	"dosage" varchar(100),
	"frequency" varchar(100),
	"time" varchar(100),
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "memory_photos" (
	"id" serial PRIMARY KEY NOT NULL,
	"photoname" varchar(255) NOT NULL,
	"description" text,
	"context_and_story" text,
	"file" varchar(500) NOT NULL,
	"tags" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "patients" ALTER COLUMN "age" SET DEFAULT 0;--> statement-breakpoint
ALTER TABLE "patients" ALTER COLUMN "age" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "patients" ALTER COLUMN "care_level" SET DEFAULT 'low';--> statement-breakpoint
ALTER TABLE "users" ALTER COLUMN "role" SET DEFAULT 'patient';--> statement-breakpoint
ALTER TABLE "users" ALTER COLUMN "care_level" SET DEFAULT 'low';--> statement-breakpoint
ALTER TABLE "facilities" ADD COLUMN "promo_code" varchar;--> statement-breakpoint
ALTER TABLE "facilities" ADD COLUMN "stripe_product_id" varchar;--> statement-breakpoint
ALTER TABLE "facilities" ADD COLUMN "stripe_price_id" varchar;--> statement-breakpoint
ALTER TABLE "facilities" ADD COLUMN "stripe_coupon_id" varchar;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "relation_to_patient" varchar;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "patient_access_code" varchar;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "facility_staff_facility_id" varchar;--> statement-breakpoint
ALTER TABLE "medications" ADD CONSTRAINT "medications_patient_id_patients_id_fk" FOREIGN KEY ("patient_id") REFERENCES "public"."patients"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_facility_staff_facility_id_facilities_id_fk" FOREIGN KEY ("facility_staff_facility_id") REFERENCES "public"."facilities"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "users" DROP COLUMN "age";