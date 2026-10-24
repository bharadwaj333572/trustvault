import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        ink: {
          DEFAULT: "#0B1220",
          light: "#162032",
          dark: "#050911",
          muted: "#1E2B42",
        },
        paper: {
          DEFAULT: "#F0EFEA",
          dark: "#E3E0D8",
          light: "#F7F6F3",
          muted: "#D7D3C8",
        },
        accent: {
          DEFAULT: "#FF5A1F",
          hover: "#E04812",
          muted: "rgba(255, 90, 31, 0.12)",
        },
        denied: {
          DEFAULT: "#E5484D",
          muted: "rgba(229, 72, 77, 0.12)",
        },
        allowed: {
          DEFAULT: "#30A46C",
          muted: "rgba(48, 164, 108, 0.12)",
        },
        border: {
          dark: "rgba(255, 255, 255, 0.10)",
          light: "rgba(11, 18, 32, 0.12)",
        },
      },
      fontFamily: {
        mono: ["JetBrains Mono", "SFMono-Regular", "Menlo", "Monaco", "Consolas", "monospace"],
        sans: ["Inter", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "sans-serif"],
        display: ["Space Grotesk", "Archivo", "Inter", "sans-serif"],
      },
      borderRadius: {
        DEFAULT: "4px",
        sm: "2px",
        md: "4px",
        lg: "6px",
      },
    },
  },
  plugins: [],
};

export default config;
