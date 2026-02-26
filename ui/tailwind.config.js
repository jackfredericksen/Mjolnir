/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        mjolnir: {
          50: '#f0f4ff',
          100: '#dde5ff',
          200: '#c2d0ff',
          300: '#96b0ff',
          400: '#6485ff',
          500: '#3b5bff',
          600: '#1a30f5',
          700: '#1422e1',
          800: '#171db6',
          900: '#191f8f',
          950: '#111257',
        },
      },
    },
  },
  plugins: [],
}
