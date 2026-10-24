import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'TrustVault — Secure Document Sharing with a Real Audit Trail',
  description:
    'The wrong person can never read a file, and we can prove who read it. Centralized policy engine, instant streaming revocation, and append-only cryptographic audit chain.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&family=Space+Grotesk:wght@700;800&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="bg-ink text-paper antialiased min-h-screen">
        {children}
      </body>
    </html>
  );
}
