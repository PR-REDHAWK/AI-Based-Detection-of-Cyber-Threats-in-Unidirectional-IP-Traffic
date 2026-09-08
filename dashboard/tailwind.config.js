/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: "#0B0F19",
          card: "#111827",
          border: "#1F2937",
          hover: "#1E293B",
          accent: "#00F0FF",
          critical: "#EF4444",
          high: "#F97316",
          medium: "#F59E0B",
          low: "#3B82F6"
        }
      }
    },
  },
  plugins: [],
}
