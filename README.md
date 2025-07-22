# Spark Shield

<div align="center">
  [![Live Demo](https://img.shields.io/badge/Live%20Demo-Vercel-brightgreen?style=for-the-badge&logo=vercel)](https://spark-shield.vercel.app)
  ![React](https://img.shields.io/badge/React-18+-blue?style=for-the-badge&logo=react)
  ![TypeScript](https://img.shields.io/badge/TypeScript-4+-3178c6?style=for-the-badge&logo=typescript)
  ![Vite](https://img.shields.io/badge/Vite-Latest-646CFF?style=for-the-badge&logo=vite)
  ![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3-38B2AC?style=for-the-badge&logo=tailwind-css)
</div>

## About
A comprehensive security scanning platform designed to detect and analyze potential security threats. Features include domain scanning, IP analysis, phishing detection, and file scanning capabilities.

🔗 **[Live Demo](https://spark-shield.vercel.app)**

## Features
- Domain and IP scanning
- Git repository security analysis
- Website vulnerability scanning
- Phishing detection
- File scanning and analysis
- Code repair suggestions
- Real-time scan results
- Dark/Light theme support

## Tech Stack
- React 18+
- TypeScript
- Vite
- TailwindCSS
- Bun Runtime
- Shadcn/ui

## Getting Started

```bash
# Frontend Setup
cd frontend
npm install
npm run dev

# Backend Setup
cd backend
bun install
bun --watch index.js
```

## Project Structure
```
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── ui/          # Shadcn UI components
│   │   │   └── ...          # Custom components
│   │   ├── hooks/           # Custom hooks
│   │   ├── lib/             # Utilities
│   │   ├── pages/           # Page components
│   │   └── App.tsx          # Main app component
│   └── public/              # Static assets
└── backend/
    ├── lib/                 # Server utilities
    └── index.js            # Server entry
```