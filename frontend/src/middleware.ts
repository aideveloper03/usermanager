import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server';
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Define public routes that don't require authentication
const isPublicRoute = createRouteMatcher([
  '/',
  '/sign-in(.*)',
  '/sign-up(.*)',
  '/api/webhook(.*)',
  '/api/health(.*)',
]);

// Define routes that should be completely ignored
const isIgnoredRoute = createRouteMatcher([
  '/_next(.*)',
  '/favicon.ico',
  '/api/health(.*)',
]);

// Clerk middleware with simplified configuration
// Protection is handled at the page/layout level for better flexibility
export default clerkMiddleware((auth, req: NextRequest) => {
  // Skip middleware processing for ignored routes
  if (isIgnoredRoute(req)) {
    return NextResponse.next();
  }
  
  // For public routes, continue without requiring auth
  if (isPublicRoute(req)) {
    return NextResponse.next();
  }
  
  // For protected routes, the page components will handle auth checks
  // using useAuth() hook or auth() helper
  return NextResponse.next();
});

export const config = {
  matcher: [
    // Skip Next.js internals and all static files
    '/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)',
    // Always run for API routes
    '/(api|trpc)(.*)',
  ],
};
