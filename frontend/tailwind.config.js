const { theme } = require('./src/styles/theme');

/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: theme.colors,
      fontFamily: {
        sans: [theme.typography.fontFamily, 'sans-serif'],
      },
      fontSize: theme.typography,
      spacing: theme.spacing,
      borderRadius: theme.borderRadius,
      boxShadow: theme.shadows,
      transitionDuration: {
        DEFAULT: theme.transitions.duration,
      },
      transitionTimingFunction: {
        DEFAULT: theme.transitions.timing,
      },
    },
  },
  plugins: [],
}

