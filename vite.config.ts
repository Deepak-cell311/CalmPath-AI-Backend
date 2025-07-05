import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // this is needed to expose the server to the network
    // so that it can be accessed from the replit webview
    host: "0.0.0.0",
    port: 3000,
  },
});