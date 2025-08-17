const fs = require('fs');
const path = require('path');

console.log('🔍 Debugging uploads directory...\n');

// Check current directory
console.log('Current directory:', process.cwd());
console.log('__dirname:', __dirname);

// Check if we're in the right location
const serverDir = path.join(__dirname, '../dist/server');
const uploadsDir = path.join(serverDir, 'uploads');

console.log('\n📁 Directory paths:');
console.log('Server directory:', serverDir);
console.log('Uploads directory:', uploadsDir);

// Check if directories exist
console.log('\n✅ Directory existence:');
console.log('Server directory exists:', fs.existsSync(serverDir));
console.log('Uploads directory exists:', fs.existsSync(uploadsDir));

if (fs.existsSync(uploadsDir)) {
    try {
        const files = fs.readdirSync(uploadsDir);
        console.log('\n📄 Files in uploads directory:');
        files.forEach(file => {
            const filePath = path.join(uploadsDir, file);
            const stats = fs.statSync(filePath);
            console.log(`  - ${file} (${stats.size} bytes, ${stats.mtime})`);
        });
        
        // Check permissions
        const stats = fs.statSync(uploadsDir);
        console.log('\n🔐 Uploads directory permissions:');
        console.log('Mode:', stats.mode.toString(8));
        console.log('Is directory:', stats.isDirectory());
        console.log('Is readable:', fs.accessSync(uploadsDir, fs.constants.R_OK) ? 'Yes' : 'No');
        console.log('Is writable:', fs.accessSync(uploadsDir, fs.constants.W_OK) ? 'Yes' : 'No');
        
    } catch (error) {
        console.error('❌ Error reading uploads directory:', error.message);
    }
} else {
    console.log('\n❌ Uploads directory does not exist!');
    console.log('Creating uploads directory...');
    
    try {
        fs.mkdirSync(uploadsDir, { recursive: true });
        console.log('✅ Created uploads directory');
        
        // Set permissions
        fs.chmodSync(uploadsDir, 0o755);
        console.log('✅ Set permissions to 755');
        
    } catch (error) {
        console.error('❌ Error creating uploads directory:', error.message);
    }
}

// Test file creation
console.log('\n🧪 Testing file creation...');
const testFile = path.join(uploadsDir, 'test.txt');
try {
    fs.writeFileSync(testFile, 'test content');
    console.log('✅ Successfully created test file');
    
    // Clean up
    fs.unlinkSync(testFile);
    console.log('✅ Successfully deleted test file');
    
} catch (error) {
    console.error('❌ Error with file operations:', error.message);
}

console.log('\n🎯 Debug complete!');
