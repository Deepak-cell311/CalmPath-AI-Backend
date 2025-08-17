const fs = require('fs');
const path = require('path');

// Ensure uploads directory exists
const uploadsPath = path.resolve(__dirname, "../dist/server/uploads");

try {
  if (!fs.existsSync(uploadsPath)) {
    fs.mkdirSync(uploadsPath, { recursive: true });
    console.log(`Created uploads directory: ${uploadsPath}`);
  } else {
    console.log(`Uploads directory already exists: ${uploadsPath}`);
  }

  // Set permissions (ignored on Windows, works on Linux)
  fs.chmodSync(uploadsPath, 0o755);
  console.log("Set permissions for uploads directory");
} catch (error) {
  console.error("Error setting up uploads directory:", error);
  process.exit(1);
}

