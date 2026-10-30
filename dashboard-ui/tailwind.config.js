/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        sentinel: {
          900: '#0a0f1d',
          800: '#111827',
          700: '#1e293b',
          accent: '#3b82f6',
        },
      },
    },
  },
  plugins: [],
};
