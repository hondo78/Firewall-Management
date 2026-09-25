import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev-Server: Backend lokal auf :8000 erwartet
export default defineConfig({
  plugins: [react()],
  server: { proxy: { '/api': 'http://localhost:8000' } },
})
