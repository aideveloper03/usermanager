# Clerk Integration Guide

Complete guide for setting up Clerk authentication with the N8N Orchestration Gateway.

## Overview

The gateway uses Clerk's native Supabase integration for seamless authentication:

- **Frontend**: Clerk UI components for sign-in/sign-up
- **Backend**: JWT verification via JWKS
- **Database**: Native RLS integration with `auth.clerk_user_id()`

## 1. Clerk Setup

### Create Clerk Application

1. Go to [Clerk Dashboard](https://dashboard.clerk.com)
2. Create a new application
3. Choose authentication methods (email, social, etc.)
4. Note your API keys:
   - `CLERK_PUBLISHABLE_KEY` (pk_test_xxx or pk_live_xxx)
   - `CLERK_SECRET_KEY` (sk_test_xxx or sk_live_xxx)

### Configure JWT

1. Go to **JWT Templates** (or it's auto-configured with Supabase integration)
2. The default template includes:
   - `sub`: User ID (user_xxxxx)
   - `org_id`: Organization ID (if using Clerk Organizations)
   - `org_role`: User's role in organization

### Enable Supabase Integration

1. Go to **Integrations** → **Supabase**
2. Click "Enable"
3. Enter your Supabase project URL
4. Copy the provided JWT configuration

## 2. Backend Configuration

### Environment Variables

```bash
# .env
CLERK_SECRET_KEY=sk_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
CLERK_PUBLISHABLE_KEY=pk_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
CLERK_JWT_ISSUER=https://your-instance.clerk.accounts.dev
CLERK_JWKS_URL=https://your-instance.clerk.accounts.dev/.well-known/jwks.json
```

### JWT Verification

The gateway verifies JWTs using JWKS:

```python
# app/core/security.py
class ClerkJWTVerifier:
    async def verify_token(self, token: str) -> dict:
        # 1. Decode header to get key ID (kid)
        # 2. Fetch JWKS from Clerk
        # 3. Find matching signing key
        # 4. Verify signature and claims
        # 5. Return decoded claims
```

### Extract User Information

```python
# After verification
claims = await jwt_verifier.verify_token(token)
user_id = claims["sub"]       # "user_xxxxx"
org_id = claims.get("org_id") # "org_xxxxx" or None
```

## 3. Frontend Setup

### Install Dependencies

```bash
cd frontend
npm install @clerk/nextjs
```

### Configure Environment

```bash
# frontend/.env.local
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_xxxxx
CLERK_SECRET_KEY=sk_test_xxxxx
NEXT_PUBLIC_CLERK_SIGN_IN_URL=/sign-in
NEXT_PUBLIC_CLERK_SIGN_UP_URL=/sign-up
NEXT_PUBLIC_CLERK_AFTER_SIGN_IN_URL=/dashboard
NEXT_PUBLIC_CLERK_AFTER_SIGN_UP_URL=/dashboard
```

### Wrap Application

```tsx
// src/app/layout.tsx
import { ClerkProvider } from '@clerk/nextjs';

export default function RootLayout({ children }) {
  return (
    <ClerkProvider>
      <html>
        <body>{children}</body>
      </html>
    </ClerkProvider>
  );
}
```

### Sign In Page

```tsx
// src/app/sign-in/[[...sign-in]]/page.tsx
import { SignIn } from '@clerk/nextjs';

export default function SignInPage() {
  return (
    <SignIn
      routing="path"
      path="/sign-in"
      signUpUrl="/sign-up"
      afterSignInUrl="/dashboard"
    />
  );
}
```

### Sign Up Page

```tsx
// src/app/sign-up/[[...sign-up]]/page.tsx
import { SignUp } from '@clerk/nextjs';

export default function SignUpPage() {
  return (
    <SignUp
      routing="path"
      path="/sign-up"
      signInUrl="/sign-in"
      afterSignUpUrl="/dashboard"
    />
  );
}
```

### Protected Pages

```tsx
// src/app/dashboard/page.tsx
import { auth } from '@clerk/nextjs';
import { redirect } from 'next/navigation';

export default async function DashboardPage() {
  const { userId } = auth();
  
  if (!userId) {
    redirect('/sign-in');
  }
  
  return <div>Welcome to Dashboard</div>;
}
```

### Using the Token

```tsx
// Client component
'use client';
import { useAuth } from '@clerk/nextjs';

export function ApiClient() {
  const { getToken } = useAuth();
  
  async function callGateway() {
    const token = await getToken();
    
    const response = await fetch('http://localhost:8000/api/v1/workflows', {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });
    
    return response.json();
  }
}
```

## 4. Middleware Configuration

### Protect Routes

```typescript
// src/middleware.ts
import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server';

const isPublicRoute = createRouteMatcher([
  '/',
  '/sign-in(.*)',
  '/sign-up(.*)',
]);

export default clerkMiddleware((auth, req) => {
  if (!isPublicRoute(req)) {
    auth().protect();
  }
});
```

## 5. User Profile Sync

### Webhook Setup

1. In Clerk Dashboard → **Webhooks**
2. Create endpoint: `https://your-gateway.com/api/v1/webhooks/clerk`
3. Select events:
   - `user.created`
   - `user.updated`
   - `user.deleted`
4. Copy the signing secret

### Webhook Handler

```python
# app/api/v1/endpoints/webhooks.py
from svix.webhooks import Webhook

@router.post("/webhooks/clerk")
async def clerk_webhook(request: Request):
    # Verify webhook signature
    webhook = Webhook(settings.clerk_webhook_secret)
    payload = await request.body()
    headers = dict(request.headers)
    
    try:
        event = webhook.verify(payload, headers)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid signature")
    
    event_type = event["type"]
    data = event["data"]
    
    if event_type == "user.created":
        await db.create_profile({
            "id": data["id"],
            "email": data["email_addresses"][0]["email_address"],
            "name": f"{data['first_name']} {data['last_name']}",
        })
    elif event_type == "user.updated":
        await db.update_profile(data["id"], {...})
    elif event_type == "user.deleted":
        await db.deactivate_profile(data["id"])
    
    return {"success": True}
```

## 6. Organization Support

### Enable Clerk Organizations

1. In Clerk Dashboard → **Organizations** → Enable
2. Configure membership roles

### Access Organization in Backend

```python
# Organization ID from JWT
org_id = claims.get("org_id")  # "org_xxxxx"
org_role = claims.get("org_role")  # "admin", "member", etc.

# Or from header (for API key auth)
org_id = request.headers.get("X-Tenant-ID")
```

### Organization Switcher

```tsx
import { OrganizationSwitcher } from '@clerk/nextjs';

export function Header() {
  return (
    <header>
      <OrganizationSwitcher />
    </header>
  );
}
```

## 7. User Components

### User Button

```tsx
import { UserButton } from '@clerk/nextjs';

export function Header() {
  return (
    <header>
      <UserButton afterSignOutUrl="/" />
    </header>
  );
}
```

### Signed In/Out Conditional

```tsx
import { SignedIn, SignedOut } from '@clerk/nextjs';

export function NavBar() {
  return (
    <nav>
      <SignedOut>
        <a href="/sign-in">Sign In</a>
      </SignedOut>
      <SignedIn>
        <a href="/dashboard">Dashboard</a>
      </SignedIn>
    </nav>
  );
}
```

## 8. Developer Bypass

For development without Clerk:

```bash
# Gateway .env
DEV_SKIP_AUTH=true
DEV_DEFAULT_USER_ID=dev_user_001
DEV_DEFAULT_ORG_ID=dev_org_001
```

```bash
# Test request with bypass
curl -X GET http://localhost:8000/api/v1/workflows \
  -H "X-Dev-User-ID: test_user" \
  -H "X-Dev-Org-ID: test_org"
```

## 9. Security Best Practices

1. **Never expose secret key**: Keep `CLERK_SECRET_KEY` server-side only
2. **Validate tokens**: Always verify JWT signatures
3. **Check expiration**: Reject expired tokens
4. **Use HTTPS**: Encrypt all traffic in production
5. **Rotate keys**: Periodically rotate API keys
6. **Monitor webhooks**: Log and alert on suspicious activity

## 10. Troubleshooting

### Common Issues

**"JWT verification failed"**
- Check JWKS URL is correct
- Verify token hasn't expired
- Ensure issuer matches

**"Missing user ID in claims"**
- Token might be from different Clerk instance
- Check JWT template includes `sub` claim

**"Organization not found"**
- User might not have selected an organization
- Check `org_id` claim or use X-Tenant-ID header

### Debug Token

```javascript
// Decode token without verification (for debugging only)
const [header, payload, signature] = token.split('.');
const claims = JSON.parse(atob(payload));
console.log(claims);
```
