/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        nordic: {
          bg: '#f8fafc',       // Slate 50
          card: '#ffffff',     // Clean white
          border: '#e2e8f0',   // Slate 200
          text: '#0f172a',     // Slate 900
          muted: '#64748b',    // Slate 500
          accent: '#2563eb',   // Nordic crisp blue
        }
      },
      maxWidth: {
        '8xl': '80rem',
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Menlo', 'Monaco', 'Courier New', 'monospace'],
      }
    },
  },
  plugins: [],
}
