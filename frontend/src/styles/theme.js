// frontend/src/styles/theme.js

const theme = {
  colors: {
    background: '#121212', // Deeper black
    surface: '#1E1E1E',    // Darker surface for better contrast
    primary: '#00CFE8',   // A slightly softer, more modern cyan
    secondary: '#F000B8', // Vibrant magenta for a futuristic accent
    text: '#EAEAEA',        // Slightly brighter text for readability
    textSecondary: '#A0A0A0', // Kept for consistency
    success: '#00FF7F',   // A punchier green
    error: '#FF4444',     // Standard error red
    warning: '#FFBB33',   // Standard warning amber
    border: '#333333',      // More subtle borders
  },
  typography: {
    fontFamily: "'Inter', sans-serif", // Modern, clean sans-serif font
    h1: '2.5rem',
    h2: '2rem',
    h3: '1.75rem',
    h4: '1.5rem',
    body: '1rem',
    caption: '0.875rem',
  },
  spacing: {
    xs: '4px',
    sm: '8px',
    md: '16px',
    lg: '24px',
    xl: '32px',
  },
  borderRadius: {
    sm: '4px',
    md: '8px',
    lg: '12px',
  },
  shadows: {
    sm: '0 2px 4px rgba(0, 0, 0, 0.2)',
    md: '0 4px 8px rgba(0, 0, 0, 0.3)',
    lg: '0 6px 12px rgba(0, 0, 0, 0.4)',
  },
  transitions: {
    duration: '0.3s',
    timing: 'ease-in-out',
  },
};

module.exports = { theme }; 