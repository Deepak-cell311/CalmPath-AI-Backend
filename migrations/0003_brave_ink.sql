CREATE TABLE "facility_invite_packages" (
	"id" serial PRIMARY KEY NOT NULL,
	"facility_id" varchar NOT NULL,
	"package_name" varchar(100) NOT NULL,
	"invite_count" integer NOT NULL,
	"price_in_cents" integer NOT NULL,
	"stripe_price_id" varchar,
	"is_active" boolean DEFAULT true,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "facility_invite_purchases" (
	"id" serial PRIMARY KEY NOT NULL,
	"facility_id" varchar NOT NULL,
	"package_id" integer NOT NULL,
	"stripe_session_id" varchar,
	"stripe_payment_intent_id" varchar,
	"total_paid_in_cents" integer NOT NULL,
	"invite_count" integer NOT NULL,
	"status" varchar DEFAULT 'pending',
	"purchased_at" timestamp DEFAULT now(),
	"completed_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "facility_invites" (
	"id" serial PRIMARY KEY NOT NULL,
	"facility_id" varchar NOT NULL,
	"purchase_id" integer NOT NULL,
	"invite_code" varchar(20) NOT NULL,
	"invited_email" varchar,
	"invited_phone" varchar,
	"invited_name" varchar(100),
	"status" varchar DEFAULT 'unused',
	"used_by_user_id" varchar,
	"used_at" timestamp,
	"expires_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "facility_invites_invite_code_unique" UNIQUE("invite_code")
);
--> statement-breakpoint
CREATE TABLE "personal_info" (
	"id" serial PRIMARY KEY NOT NULL,
	"patient_id" integer NOT NULL,
	"work" text,
	"family" text,
	"hobbies" text,
	"food" text,
	"other" text,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "reminders" (
	"id" serial PRIMARY KEY NOT NULL,
	"patient_id" integer NOT NULL,
	"created_by" varchar,
	"message" text NOT NULL,
	"scheduled_time" timestamp NOT NULL,
	"is_active" boolean DEFAULT true,
	"is_completed" boolean DEFAULT false,
	"completed_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
ALTER TABLE "facilities" ADD COLUMN "monthly_price" varchar;--> statement-breakpoint
ALTER TABLE "facilities" ADD COLUMN "tagline" varchar(255);--> statement-breakpoint
ALTER TABLE "facilities" ADD COLUMN "logo_url" varchar(255);--> statement-breakpoint
ALTER TABLE "facilities" ADD COLUMN "brand_color" varchar(16);--> statement-breakpoint
ALTER TABLE "memory_photos" ADD COLUMN "uploaded_by" varchar(255);--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "used_invite_code" boolean DEFAULT false;--> statement-breakpoint
ALTER TABLE "facility_invite_packages" ADD CONSTRAINT "facility_invite_packages_facility_id_facilities_id_fk" FOREIGN KEY ("facility_id") REFERENCES "public"."facilities"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "facility_invite_purchases" ADD CONSTRAINT "facility_invite_purchases_facility_id_facilities_id_fk" FOREIGN KEY ("facility_id") REFERENCES "public"."facilities"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "facility_invite_purchases" ADD CONSTRAINT "facility_invite_purchases_package_id_facility_invite_packages_id_fk" FOREIGN KEY ("package_id") REFERENCES "public"."facility_invite_packages"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "facility_invites" ADD CONSTRAINT "facility_invites_facility_id_facilities_id_fk" FOREIGN KEY ("facility_id") REFERENCES "public"."facilities"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "facility_invites" ADD CONSTRAINT "facility_invites_purchase_id_facility_invite_purchases_id_fk" FOREIGN KEY ("purchase_id") REFERENCES "public"."facility_invite_purchases"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "facility_invites" ADD CONSTRAINT "facility_invites_used_by_user_id_users_id_fk" FOREIGN KEY ("used_by_user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "personal_info" ADD CONSTRAINT "personal_info_patient_id_patients_id_fk" FOREIGN KEY ("patient_id") REFERENCES "public"."patients"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "personal_info" ADD CONSTRAINT "personal_info_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "reminders" ADD CONSTRAINT "reminders_patient_id_patients_id_fk" FOREIGN KEY ("patient_id") REFERENCES "public"."patients"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "memory_photos" ADD CONSTRAINT "memory_photos_uploaded_by_users_id_fk" FOREIGN KEY ("uploaded_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;