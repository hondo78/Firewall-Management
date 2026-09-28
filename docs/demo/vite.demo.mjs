// Dev-Server für die Demo-Aufnahme: UI auf :18097, API der Demo-Instanz auf :18000
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
export default defineConfig({ plugins: [react()], server: { port: 18097, host: '127.0.0.1', proxy: { '/api': 'http://localhost:18000' } } })
