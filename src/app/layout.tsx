import type { Metadata } from 'next';
import './globals.css';
import InteractiveBackground from '@/components/InteractiveBackground';

export const metadata: Metadata = {
  title: 'SovereignGuard - Enterprise Secrets & Certificate Lifecycle Manager',
  description: 'Centralized multi-tenant secrets and TLS certificate lifecycle management platform integrated with Cloudflare Access Zero Trust.',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <link rel="icon" href="/favicon.ico" />
      </head>
      <body>
        <InteractiveBackground />
        {children}
      </body>
    </html>
  );
}
