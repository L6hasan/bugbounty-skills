# Hypothesis Log: *.my.kaspersky.com

## Priority Ranking: Impact × Likelihood × Exposure × Ease of Validation

---

### H001: IDOR on DeviceDetails - Cross-User Device Access
- **Target**: /MyDevices/api/DeviceDetails
- **Feature**: Device details retrieval
- **Security Boundary**: User A → User B (horizontal)
- **Security Assumption**: Server verifies deviceId belongs to authenticated session user
- **Potential Failure**: Changing deviceId parameter returns other users' device info (device name, OS, protection status, owner email)
- **Attack Scenario**: Attacker authenticates, captures own DeviceDetails request, replaces deviceId with victim's (obtained via enumeration or leakage)
- **Test Method**: Auth as Account A, get own deviceId. Auth as Account B, request A's deviceId. Compare responses.
- **Expected Secure Behavior**: 403/404 for non-owned deviceId
- **Potential Impact**: Cross-user device info disclosure (High)
- **Status**: Pending
- **Evidence**:

---

### H002: IDOR on GetLicenseDetails - Cross-User License Key Theft
- **Target**: /MyLicenses/GetLicenseDetails
- **Feature**: License details retrieval
- **Security Boundary**: User A → User B
- **Security Assumption**: Server verifies licenseId belongs to authenticated user
- **Potential Failure**: Changing licenseId returns other users' license keys, activation codes, subscription info
- **Attack Scenario**: Attacker enumerates/guesses licenseId, retrieves full license key of victim
- **Test Method**: Auth as A, get own licenseId. Auth as B, request A's licenseId.
- **Expected Secure Behavior**: 403/404 for non-owned licenseId
- **Potential Impact**: License key theft → unauthorized product activation (Critical/High)
- **Status**: Pending
- **Evidence**:

---

### H003: IDOR on Anti-Theft KMS - Remote Device Control
- **Target**: /api/kms/management/SendCommand, /api/kms/info/RecoveryCode
- **Feature**: Anti-theft device commands
- **Security Boundary**: Device owner → Other device owners
- **Security Assumption**: Server verifies deviceId is owned by authenticated user before executing KMS commands
- **Potential Failure**: Attacker can send lock/scream/locate/wipe commands to other users' devices, or retrieve recovery codes
- **Attack Scenario**: IDOR on deviceId in SendCommand → remote lock/wipe of victim's device
- **Test Method**: Auth as A with anti-theft enabled device. Auth as B, attempt SendCommand with A's deviceId.
- **Expected Secure Behavior**: 403 for non-owned deviceId
- **Potential Impact**: Remote device control, data destruction, ransomware-like impact (Critical)
- **Status**: Pending
- **Evidence**:

---

### H004: IDOR on LinkedAccounts - Cross-Family Sub-Account Management
- **Target**: /LinkedAccounts/Info, /LinkedAccounts/RevokeLicenseFromUser
- **Feature**: Family sharing / sub-account management
- **Security Boundary**: Master Account A → Master Account B (cross-family)
- **Security Assumption**: Server verifies target userId belongs to caller's family group
- **Potential Failure**: Changing userId allows viewing/revoking licenses of other families' sub-accounts
- **Attack Scenario**: Attacker enumerates userIds, revokes licenses from other users' families
- **Test Method**: Auth as A (with sub-accounts). Auth as B, call LinkedAccounts/Info with A's sub-account userId.
- **Expected Secure Behavior**: 403 for non-family userId
- **Potential Impact**: Cross-family account management, license disruption (High)
- **Status**: Pending
- **Evidence**:

---

### H005: IDOR on MyAccountApi - Cross-User Profile Access
- **Target**: /MyAccountApi, /MyAccountApi/OrdersHistory
- **Feature**: Account settings and order history
- **Security Boundary**: User A → User B
- **Security Assumption**: Account data scoped to session user
- **Potential Failure**: Parameter manipulation returns other users' profile/PII/order history
- **Attack Scenario**: Attacker modifies request to access victim's email, phone, order history (addresses, payment last4)
- **Test Method**: Compare responses between two authenticated accounts; test userId parameter injection
- **Expected Secure Behavior**: Session-scoped data only
- **Potential Impact**: PII disclosure, order/payment info leak (High)
- **Status**: Pending
- **Evidence**:

---

### H006: IDOR on PaymentMethods - Cross-User Payment Method Access
- **Target**: /AccountSettings/PaymentMethodsApi/PaymentMethods
- **Feature**: Payment method listing
- **Security Boundary**: User A → User B
- **Security Assumption**: Payment methods scoped to authenticated user
- **Potential Failure**: Attacker retrieves other users' saved payment methods (card last4, type, expiry)
- **Attack Scenario**: IDOR on paymentMethodId or user context
- **Test Method**: Auth as A, get own payment methods. Auth as B, attempt access with A's IDs.
- **Expected Secure Behavior**: Session-scoped only
- **Potential Impact**: Payment instrument disclosure (High, PCI)
- **Status**: Pending
- **Evidence**:

---

### H007: IDOR on Safe Kids Child Data - Cross-Family Child Access
- **Target**: /MyKids/GlobalContext, /SafeKids/api/Rules/*, /ProductsSafeKids/DeviceUsageJson/*
- **Feature**: Parental control
- **Security Boundary**: Parent A → Parent B (cross-family), Parent → Other children
- **Security Assumption**: childId scoped to parent's family
- **Potential Failure**: Changing childId returns other families' children's location, device usage, web categories
- **Attack Scenario**: Enumerate childIds, retrieve minor's location data
- **Test Method**: Auth as parent A (with children). Auth as parent B, request A's childId data.
- **Expected Secure Behavior**: 403 for non-owned childId
- **Potential Impact**: Minor's location/PII disclosure (Critical)
- **Status**: Pending
- **Evidence**:

---

### H008: CSRF on State-Changing Endpoints
- **Target**: Multiple POST endpoints (ChangeAlias, TurnOffAutoRenew, DeleteDevice, DisablePhoneFactor)
- **Feature**: State-changing operations
- **Security Boundary**: Cross-origin → Authenticated session
- **Security Assumption**: CSRF tokens present and validated on all state-changing requests
- **Potential Failure**: Missing/weak CSRF protection allows cross-site form submission
- **Attack Scenario**: Attacker crafts HTML page that auto-submits to /MyAccountApi/ChangeAlias or /LinkedAccounts/RevokeLicenseFromUser
- **Test Method**: Check for XSRF token in responses/cookies; test POST without token
- **Expected Secure Behavior**: CSRF token required and validated
- **Potential Impact**: Unauthorized settings changes, license revocation (High)
- **Status**: Pending
- **Evidence**:

---

### H009: 2FA Bypass on Sensitive Operations
- **Target**: /ActionsAuthorization/ConfirmPasswordLite, 2FA setup/disable endpoints
- **Feature**: Step-up authentication
- **Security Boundary**: Authenticated user → Sensitive action
- **Security Assumption**: Sensitive ops (password change, 2FA disable, account deletion) require password re-confirmation or 2FA
- **Potential Failure**: Sensitive endpoints accessible with session cookie alone, no step-up auth
- **Attack Scenario**: XSS/CSRF attacker disables 2FA or changes password without re-auth
- **Test Method**: Call sensitive endpoints with valid session but skip ConfirmPasswordLite
- **Expected Secure Behavior**: Step-up auth required
- **Potential Impact**: Account takeover facilitation (High)
- **Status**: Pending
- **Evidence**:

---

### H010: Sub-Account Privilege Escalation
- **Target**: /CreateSubAccount, /SubAccountInvitation/*, master-only endpoints
- **Feature**: Family account hierarchy
- **Security Boundary**: Sub-account → Master account
- **Security Assumption**: Sub-accounts cannot access master-only functions (invite, license management, other sub-accounts)
- **Potential Failure**: Sub-account session can invoke master-only APIs
- **Attack Scenario**: Child account escalates to master privileges
- **Test Method**: Auth as sub-account, call master-only endpoints
- **Expected Secure Behavior**: Role check rejects sub-account
- **Potential Impact**: Privilege escalation within family (Medium/High)
- **Status**: Pending
- **Evidence**:

---

### H011: Invitation Token Predictability / IDOR
- **Target**: /SubAccountInvitation/Validate, /SubAccountInvitation/AcceptFromBanner
- **Feature**: Invitation acceptance
- **Security Boundary**: Invitee → Invitation owner's family
- **Security Assumption**: Invitation tokens are high-entropy, single-use, bound to email
- **Potential Failure**: Predictable tokens, token reuse, accepting invitation without email ownership proof
- **Attack Scenario**: Attacker brute-forces/guesses invitation token, joins victim's family
- **Test Method**: Capture invitation flow, analyze token entropy, test reuse
- **Expected Secure Behavior**: High entropy, single-use, email-bound
- **Potential Impact**: Unauthorized family membership → license access (High)
- **Status**: Pending
- **Evidence**:

---

### H012: Password Reset Token Issues
- **Target**: /PasswordRecovery/AjaxPasswordRecovery, /PasswordRecovery/AjaxReset
- **Feature**: Password reset
- **Security Boundary**: Unauthenticated → Account takeover
- **Security Assumption**: Reset tokens are random, single-use, time-limited, bound to account
- **Potential Failure**: Token leakage in response, predictable tokens, host header injection in reset email, race conditions
- **Attack Scenario**: Token predictability or leakage enables password reset without email access
- **Test Method**: Request reset for controlled account, analyze token; test host header; test race
- **Expected Secure Behavior**: Secure token generation and validation
- **Potential Impact**: Account takeover (Critical)
- **Status**: Pending
- **Evidence**:

---

### H013: Mass Assignment on Profile Update
- **Target**: /MyAccountApi/ChangeAlias, /api/account/change-alias, profile update endpoints
- **Feature**: Profile modification
- **Security Boundary**: User → Own profile fields
- **Security Assumption**: Only expected fields (alias) are accepted; privileged fields (role, isMaster, email) are ignored
- **Potential Failure**: Sending additional JSON fields (role, email, isCorporate) modifies privileged attributes
- **Attack Scenario**: Attacker sends `{"alias":"x", "role":"master", "email":"attacker@evil.com"}` to escalate
- **Test Method**: Inject extra fields in POST body, check if they persist
- **Expected Secure Behavior**: Allowlist of mutable fields
- **Potential Impact**: Privilege escalation, email change → ATO (High)
- **Status**: Pending
- **Evidence**:

---

### H014: Open Redirect via returnUrl / logonContext
- **Target**: /?returnUrl=, /Redirect, logonContext parameter
- **Feature**: Post-auth redirect
- **Security Boundary**: Authenticated user → External site
- **Security Assumption**: returnUrl validated against allowlist
- **Potential Failure**: returnUrl accepts external URLs → phishing
- **Attack Scenario**: Craft login URL with returnUrl=https://evil.com, victim logs in, redirected to phishing page
- **Test Method**: Test various returnUrl payloads on login flow
- **Expected Secure Behavior**: Only relative paths or same-origin URLs accepted
- **Potential Impact**: Credential phishing facilitation (Medium)
- **Status**: Pending
- **Evidence**:

---

### H015: WebSocket Hijacking on SignalR (/signalr/changes)
- **Target**: /signalr/changes
- **Feature**: Real-time device status
- **Security Boundary**: Cross-origin → User's device stream
- **Security Assumption**: WebSocket upgrade validates Origin header
- **Potential Failure**: Origin not checked → attacker page connects to victim's SignalR hub
- **Attack Scenario**: Malicious page opens WebSocket to /signalr/changes with victim's cookies, receives device status updates
- **Test Method**: Attempt WebSocket upgrade from cross-origin, check Origin validation
- **Expected Secure Behavior**: Origin validation rejects cross-site
- **Potential Impact**: Real-time device status leak (Medium/High)
- **Status**: Pending
- **Evidence**:

---

### H016: CORS Misconfiguration
- **Target**: All API endpoints
- **Feature**: Cross-origin resource sharing
- **Security Boundary**: Cross-origin browser → Authenticated API
- **Security Assumption**: CORS not reflecting untrusted origins with credentials
- **Potential Failure**: Access-Control-Allow-Origin reflects attacker origin + Allow-Credentials: true
- **Attack Scenario**: Attacker page reads authenticated API responses via fetch with credentials
- **Test Method**: Send Origin: https://evil.com, check ACAO and ACAC headers
- **Expected Secure Behavior**: No reflection, or strict allowlist
- **Potential Impact**: Cross-origin data theft (High)
- **Status**: Pending (initial test showed no ACAO on /api/regions - good)
- **Evidence**:

---

### H017: Unauthenticated Access to Sensitive Endpoints
- **Target**: Various API endpoints
- **Feature**: Authentication boundary
- **Security Boundary**: Unauthenticated → Authenticated-only data
- **Security Assumption**: All user-data endpoints require valid session
- **Potential Failure**: Some endpoints accessible without auth (forced browsing)
- **Attack Scenario**: Direct API access without cookies returns user data
- **Test Method**: Call each API endpoint without auth cookies, compare responses
- **Expected Secure Behavior**: 401/403 without auth
- **Potential Impact**: Unauthenticated data access (Critical if successful)
- **Status**: Pending
- **Evidence**:

---

### H018: HTTP Method Tampering
- **Target**: Endpoints with restricted methods
- **Feature**: HTTP method enforcement
- **Security Boundary**: Method-based access control
- **Security Assumption**: Dangerous methods (DELETE, PUT) properly restricted
- **Potential Failure**: GET endpoint also accepts DELETE/PUT, or method override (X-HTTP-Method-Override)
- **Attack Scenario**: Change GET to DELETE on resource endpoints
- **Test Method**: Test alternate HTTP methods on key endpoints
- **Expected Secure Behavior**: Only intended methods allowed
- **Potential Impact**: Unauthorized modifications (Medium)
- **Status**: Pending
- **Evidence**:

---

### H019: Session Fixation
- **Target**: Login flow
- **Feature**: Session management
- **Security Boundary**: Pre-auth → Post-auth session
- **Security Assumption**: Session ID regenerated after successful login
- **Potential Failure**: Session cookie value same before and after login
- **Attack Scenario**: Attacker sets victim's session cookie, waits for login, uses same session
- **Test Method**: Capture session cookie pre-login, login, compare post-login cookie
- **Expected Secure Behavior**: Session regeneration on login
- **Potential Impact**: Session takeover (High)
- **Status**: Pending
- **Evidence**:

---

### H020: Information Disclosure in Error Messages
- **Target**: Various API endpoints, /Error/LogJsError
- **Feature**: Error handling
- **Security Boundary**: System internals → User
- **Security Assumption**: Errors don't leak stack traces, internal paths, SQL, or sensitive config
- **Potential Failure**: Verbose errors reveal internal structure
- **Attack Scenario**: Send malformed requests, analyze error responses
- **Test Method**: Fuzz endpoints with malformed data, check error bodies
- **Expected Secure Behavior**: Generic error messages
- **Potential Impact**: Facilitates other attacks (Low/Medium)
- **Status**: Pending
- **Evidence**:

---

## Ranking Summary

| ID | Hypothesis | Impact | Likelihood | Exposure | Ease | Priority |
|----|-----------|--------|------------|----------|------|----------|
| H003 | Anti-Theft KMS IDOR | Critical | Medium | Medium | Medium | 1 |
| H002 | License Key IDOR | Critical | Medium | High | High | 2 |
| H001 | DeviceDetails IDOR | High | High | High | High | 3 |
| H007 | Safe Kids Child IDOR | Critical | Medium | Medium | Medium | 4 |
| H012 | Password Reset Flaws | Critical | Low | High | Medium | 5 |
| H005 | MyAccountApi IDOR | High | High | High | High | 6 |
| H004 | LinkedAccounts IDOR | High | Medium | High | High | 7 |
| H017 | Unauth Access | Critical | Low | High | High | 8 |
| H008 | CSRF | High | Medium | High | High | 9 |
| H013 | Mass Assignment | High | Medium | Medium | High | 10 |
| H009 | 2FA Bypass | High | Low | Medium | Medium | 11 |
| H011 | Invitation Token | High | Low | Medium | Medium | 12 |
| H006 | Payment Method IDOR | High | Medium | Medium | Medium | 13 |
| H010 | Sub-Account Escalation | Medium | Low | Medium | Medium | 14 |
| H019 | Session Fixation | High | Low | High | Medium | 15 |
| H014 | Open Redirect | Medium | Medium | High | High | 16 |
| H015 | WebSocket Hijack | Medium | Low | Medium | Hard | 17 |
| H016 | CORS | High | Low | High | High | 18 |
| H018 | Method Tampering | Medium | Low | High | High | 19 |
| H020 | Error Disclosure | Low | High | High | High | 20 |
