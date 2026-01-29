import { auth } from '@clerk/nextjs/server';
import { redirect } from 'next/navigation';
import type { ReactNode } from 'react';

interface DashboardLayoutProps {
  children: ReactNode;
}

/**
 * Dashboard layout with server-side authentication check.
 * This ensures all dashboard routes require authentication.
 */
export default async function DashboardLayout({ children }: DashboardLayoutProps) {
  const { userId } = await auth();
  
  // Redirect to sign-in if not authenticated
  if (!userId) {
    redirect('/sign-in');
  }
  
  return <>{children}</>;
}
