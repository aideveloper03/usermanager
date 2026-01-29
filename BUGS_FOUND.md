# Bug Report - N8N Orchestration Gateway

## Critical Bugs

### 1. JWT Verification Uses Manual Implementation Instead of Official Clerk SDK
**Location:** `app/core/security.py`
**Issue:** The code manually fetches JWKS and verifies JWTs using python-jose. The official Clerk Python SDK (`clerk-backend-api`) provides `authenticate_request()` which is the recommended, more secure approach.
**Impact:** Potential security vulnerabilities, missing edge case handling
**Fix:** Replace with official Clerk SDK

### 2. HMAC Validation Cannot Work
**Location:** `app/api/v1/endpoints/execute.py` (lines 96-151)
**Issue:** The code stores `client_secret_hash` but cannot verify HMAC signatures because HMAC requires the raw secret, not a hash. The comment in code acknowledges this.
**Impact:** HMAC anti-hijacking feature is non-functional
**Fix:** Either store client secret encrypted in Vault (not hashed), or remove the HMAC feature

### 3. Streaming Endpoint Never Updates Completion Status
**Location:** `app/api/v1/endpoints/execute.py` (lines 440-519)
**Issue:** The `/execute/stream` endpoint deducts credits and sets status to RUNNING but never updates the usage log when streaming completes or fails.
**Impact:** Usage logs are stuck in "running" status forever, incorrect billing

## Medium Bugs

### 4. internal.py Uses Wrong Event Type String
**Location:** `app/api/v1/endpoints/internal.py` (line 65)
**Issue:** Uses string `"n8n_workflow_error"` instead of `SecurityEventType` enum
**Impact:** Type safety violation, potential runtime issues

### 5. rate_limiter.py Uses Wrong Event Type String
**Location:** `app/core/rate_limiter.py` (line 104)
**Issue:** Uses string `"rate_limit_exceeded"` instead of `SecurityEventType.RATE_LIMIT_EXCEEDED.value`
**Impact:** Type safety violation

### 6. Missing SecurityEventType for N8N Errors
**Location:** `app/models/schemas.py`
**Issue:** `SecurityEventType` enum is missing `N8N_WORKFLOW_ERROR` value
**Impact:** Cannot properly categorize n8n workflow errors

### 7. Missing Clerk Webhook Signature Verification
**Location:** No endpoint exists
**Issue:** When syncing users from Clerk webhooks, there's no Svix signature verification
**Impact:** Security vulnerability - anyone could send fake webhook payloads

## Minor Issues

### 8. UUID vs String Comparison Issues
**Location:** Multiple endpoints (`organizations.py`, `workflows.py`)
**Issue:** Comparing `str(o["id"]) == str(org_id)` is error-prone
**Fix:** Normalize to strings consistently or use proper UUID comparison

### 9. Database Service Uses Sync Client
**Location:** `app/services/database.py`
**Issue:** Uses synchronous Supabase client despite async method signatures
**Impact:** Potential blocking in async context

### 10. Missing Required Dependencies
**Location:** `requirements.txt`
**Issue:** Missing `clerk-backend-api` package for official SDK support

## Recommendations

1. **Simplify Architecture:** Remove HMAC feature since it can't work without major redesign
2. **Use Official Clerk SDK:** Replace manual JWT verification with `clerk-backend-api`
3. **Add Webhook Endpoint:** Create proper Clerk webhook handler with Svix verification
4. **Standardize UUID Handling:** Use consistent string/UUID comparison
