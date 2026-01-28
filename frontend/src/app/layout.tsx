import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import { ClerkProvider } from '@clerk/nextjs';
import './globals.css';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'N8N Orchestration Gateway',
  description: 'Execute and manage n8n workflows through a secure, multi-tenant API gateway',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <ClerkProvider
      appearance={{
        elements: {
          formButtonPrimary: 'bg-primary hover:bg-primary/90 text-primary-foreground',
          card: 'shadow-lg',
          headerTitle: 'text-foreground',
          headerSubtitle: 'text-muted-foreground',
          socialButtonsBlockButton: 'border-border',
          formFieldInput: 'border-input',
          footerActionLink: 'text-primary hover:text-primary/80',
        },
      }}
    >
      <html lang="en">
        <body className={inter.className}>
          <div className="min-h-screen bg-gradient-to-b from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800">
            {children}
          </div>
        </body>
      </html>
    </ClerkProvider>
  );
}
