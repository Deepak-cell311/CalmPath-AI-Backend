const { db } = require('../server/db');
const { memoryPhotos } = require('../shared/schema');
const { eq, like } = require('drizzle-orm');

async function updatePhotoUrls() {
  try {
    console.log('Starting photo URL update...');

    // Get your deployed backend URL - replace this with your actual Railway backend URL
    const newBackendUrl = 'https://calmpathbackend-sid-production.up.railway.app'; // REPLACE THIS

    // Find all photos with localhost URLs
    const photos = await db
      .select()
      .from(memoryPhotos)
      .where(like(memoryPhotos.file, '%localhost%'));

    console.log(`Found ${photos.length} photos with localhost URLs`);

    // Update each photo URL
    for (const photo of photos) {
      const newUrl = photo.file.replace(/http:\/\/localhost:\d+/, newBackendUrl);

      await db
        .update(memoryPhotos)
        .set({ file: newUrl })
        .where(eq(memoryPhotos.id, photo.id));

      console.log(`Updated photo ${photo.id}: ${photo.file} -> ${newUrl}`);
    }

    console.log('Photo URL update completed!');
  } catch (error) {
    console.error('Error updating photo URLs:', error);
  } finally {
    process.exit(0);
  }
}

updatePhotoUrls();
