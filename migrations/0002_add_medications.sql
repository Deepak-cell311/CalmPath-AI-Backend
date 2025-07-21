CREATE TABLE IF NOT EXISTS medications (
  id SERIAL PRIMARY KEY,
  patient_id INTEGER NOT NULL REFERENCES patients(id),
  name VARCHAR(255) NOT NULL,
  dosage VARCHAR(100),
  frequency VARCHAR(100),
  time VARCHAR(100),
  created_at TIMESTAMPTZ DEFAULT NOW()
); 