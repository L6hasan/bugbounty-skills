# Attack Surface Map: *.my.kaspersky.com

## Target Overview
- **Primary Host**: my.kaspersky.com (Angie/nginx, ASP.NET + Angular SPA)
- **Portal Version**: QebKWhvsxUO40QcAhfP1Sg
- **CNAME**: center.kaspersky.com → center-kl.geo.kaspersky.com (94.74.67.240)
- **Auth**: Kaspersky UIS (Unified Identity Service) at web.uis.kaspersky.com + local session
- **CSP**: Strict, with report-uri to /cspreport

## In-Scope Subdomains (*.my.kaspersky.com)
| Host | Status | Notes |
|------|--------|-------|
| my.kaspersky.com | 200 | Main portal |
| dc1.my.kaspersky.com | 200 | Regional instance (same backend) |
| moscow.my.kaspersky.com | 200 | Regional instance |
| toronto.my.kaspersky.com | 200 | Regional instance |
| anti-theft.my.kaspersky.com | 200 | Anti-Theft web management |
| ucp.my.kaspersky.com | 400 | mTLS required (client cert) |
| ucp-ru.my.kaspersky.com | 400 | mTLS required |
| uol.my.kaspersky.com | 302 | UOL (Brazilian bank integration) |
| www.my.kaspersky.com | - | Redirect |
| store.my.kaspersky.com | - | Store (CSP frame-src ref) |

## API Configuration Endpoints (Unauthenticated)

---

Asset: Config API
Feature: Application configuration
Endpoint: /api/config/common, /api/config/routes, /api/config/reCaptcha
HTTP Method: GET
Authentication Required: No
User Role: Unauthenticated
Important Parameters: N/A (query params accepted)
Object Identifiers: N/A
Trust Boundary: None (public config)
Potential Security Risks: Information disclosure of full API surface, feature flags, internal URLs
Notes: Returns complete route map including all backend API endpoints, feature flags, validation regexes

---

## Authentication Flow

---

Asset: Authentication
Feature: User login via UIS + local session
Endpoint: /SignIn/StartRestLogon, /SignIn/CompleteRestLogon, /SignIn/AuthenticateUser
HTTP Method: POST
Authentication Required: No (login itself)
User Role: Unauthenticated → Authenticated
Important Parameters: samlDeflatedToken, email, password, locale, gReCaptchaResponse, logonContext
Object Identifiers: UserToken from UIS
Trust Boundary: UIS (web.uis.kaspersky.com) → my.kaspersky.com session
Potential Security Risks: Session fixation, token leakage, CSRF on login, OAuth/SSO bypass
Notes: External UIS at web.uis.kaspersky.com (OUT OF SCOPE - dependency only). Local session endpoints in scope.

---

Asset: Password Recovery
Feature: Password reset flow
Endpoint: /PasswordRecovery/AjaxPasswordRecovery, /PasswordRecovery/AjaxReset
HTTP Method: POST
Authentication Required: No
User Role: Unauthenticated
Important Parameters: email, token
Object Identifiers: Reset token
Trust Boundary: Email ownership verification
Potential Security Risks: Host header injection, token predictability, user enumeration, race conditions
Notes: Host header returns 421 (blocked). /RecoverPassword page loads SPA with type=recoverPassword

---

## Device Management (IDOR Candidates)

---

Asset: Devices API
Feature: Device list and management
Endpoint: /MyDevices/api/DeviceList, /MyDevices/api/DeviceDetails, /MyDevices/api/DeleteDevice, /MyDevices/api/DeleteService, /MyDevices/api/ChangeDeviceAlias, /MyDevices/api/VerifyService
HTTP Method: GET/POST
Authentication Required: Yes
User Role: Authenticated User (Master Account)
Important Parameters: deviceId, serviceId, hardwareId, alias
Object Identifiers: deviceId (GUID?), serviceId
Trust Boundary: User A → User B (horizontal), Master → Sub-account
Potential Security Risks: IDOR on device access, cross-user device management, sub-account privilege escalation
Notes: High-value IDOR target. DeviceDetails likely accepts deviceId parameter.

---

Asset: Anti-Theft KMS API
Feature: Anti-theft commands (lock, scream, locate, wipe)
Endpoint: /api/kms/info, /api/kms/management/SendCommand, /api/kms/management/DownloadMugshotsArchive, /api/kms/info/RecoveryCode
HTTP Method: GET/POST
Authentication Required: Yes
User Role: Authenticated User (device owner)
Important Parameters: deviceId, commandType
Object Identifiers: deviceId
Trust Boundary: Device owner authorization
Potential Security Risks: IDOR on anti-theft commands (lock/wipe other users' devices), recovery code theft
Notes: CRITICAL if IDOR exists - can remotely control other users' devices

---

## License Management (IDOR Candidates)

---

Asset: Licenses API
Feature: License details and management
Endpoint: /MyLicenses/GetLicenseDetails, /MyLicenses/GetAttachingLicenses, /MyLicenses/TurnOffAutoRenew, /MyLicenses/UpdateLicenseComments
HTTP Method: GET/POST
Authentication Required: Yes
User Role: Authenticated User / License Administrator
Important Parameters: licenseId, activationCode
Object Identifiers: licenseId
Trust Boundary: License owner / sub-account family
Potential Security Risks: IDOR on license details (PII, keys), unauthorized license revocation, auto-renewal manipulation
Notes: GetLicenseDetails likely returns full license key - high value IDOR

---

Asset: Linked Accounts API
Feature: Family/sub-account license sharing
Endpoint: /LinkedAccounts/Info, /LinkedAccounts/ChangeAlias, /LinkedAccounts/RevokeLicenseFromUser, /LinkedAccounts/AssignLicenseToOnlineService
HTTP Method: GET/POST
Authentication Required: Yes
User Role: Master Account (license administrator)
Important Parameters: userId, licenseId, alias
Object Identifiers: userId (sub-account), licenseId
Trust Boundary: Master account → sub-accounts, cross-family
Potential Security Risks: IDOR to manage other families' sub-accounts, unauthorized license transfer/revocation
Notes: Critical family sharing boundary

---

## Account Settings (Sensitive)

---

Asset: Account API
Feature: Profile and security settings
Endpoint: /MyAccountApi, /api/account/settings, /api/account/change-alias, /MyAccountApi/OrdersHistory
HTTP Method: GET/POST/DELETE
Authentication Required: Yes
User Role: Authenticated User
Important Parameters: alias, email, phone
Object Identifiers: userId (implicit from session)
Trust Boundary: Self only
Potential Security Risks: IDOR on settings, mass assignment on profile fields, order history PII leak
Notes: /api/account supports DELETE (account deletion!)

---

Asset: 2FA/Security API
Feature: Two-factor authentication management
Endpoint: /MyAccountApi/Security/GetTwoFactorAuthInfo, StartPhoneFactorSetup, EnablePhoneFactor, DisablePhoneFactor, StartOtpAppAuthSetup, DisableOtpAppAuth
HTTP Method: GET/POST
Authentication Required: Yes (+ possibly password re-auth via /ActionsAuthorization/ConfirmPasswordLite)
User Role: Authenticated User
Important Parameters: phoneNumber, otpCode, secret
Object Identifiers: N/A (self)
Trust Boundary: Self only, requires password confirmation
Potential Security Risks: 2FA bypass, disable 2FA without proper re-auth, OTP brute force
Notes: Critical security control - test authorization rigorously

---

Asset: Account Deletion
Feature: Account deletion flow
Endpoint: /MyAccountApi/deletion/DeleteAccount, /api/account (DELETE), /MyAccountApi/deletion/CheckAccountDeletionAvailability
HTTP Method: POST/DELETE
Authentication Required: Yes
User Role: Authenticated User
Important Parameters: confirmation codes
Object Identifiers: N/A
Trust Boundary: Self only
Potential Security Risks: Unauthorized account deletion via CSRF/IDOR, confirmation bypass
Notes: Destructive - test carefully with controlled accounts only

---

## Password Management

---

Asset: Password Change API
Feature: Password change and expiration
Endpoint: /MyAccountApi/passwords/GetChangePasswordInfo, /MyAccountApi/passwords/ChangePassword, /MyAccountApi/passwords/ChangeAllowPasswordExpiration
HTTP Method: GET/POST
Authentication Required: Yes
User Role: Authenticated User
Important Parameters: currentPassword, newPassword
Object Identifiers: N/A
Trust Boundary: Self only
Potential Security Risks: CSRF on password change, missing current password verification, sub-account password reset by master
Notes: Check if sub-account passwords can be reset by parent without proper controls

---

## Invitation / Sub-Account

---

Asset: Sub-Account Invitation
Feature: Family sharing invitations
Endpoint: /SubAccountInvitation/Invite, /SubAccountInvitation/Validate, /SubAccountInvitation/ResendInvitation, /SubAccountInvitation/AcceptFromBanner
HTTP Method: GET/POST
Authentication Required: Yes (invite), possibly No (accept)
User Role: Master Account (invite) / Invitee (accept)
Important Parameters: email, token, invitationId
Object Identifiers: invitationId, token
Trust Boundary: Master → Invitee, cross-family invitation acceptance
Potential Security Risks: Invitation token predictability, IDOR on invitation accept, race conditions, unlimited invite abuse
Notes: Test token entropy, IDOR on ResendInvitation

---

## Downloads / Installer

---

Asset: Downloads API
Feature: Installer download and distribution
Endpoint: /DownloadsApi/All, /DownloadsApi/license-candidates, /installer/send/self, /SendShareLink/GetModel
HTTP Method: GET/POST
Authentication Required: Yes
User Role: Authenticated User
Important Parameters: licenseId, productId, email
Object Identifiers: licenseId, productId
Trust Boundary: License owner
Potential Security Risks: IDOR on license candidates (other users' licenses), share link token abuse
Notes: GetModel may return share tokens

---

## Payment / Commercial

---

Asset: Payment Methods API
Feature: Payment method management
Endpoint: /AccountSettings/PaymentMethodsApi/PaymentMethods, /PaymentUrl, /DeletePaymentMethod
HTTP Method: GET/POST
Authentication Required: Yes
User Role: Authenticated User
Important Parameters: paymentMethodId
Object Identifiers: paymentMethodId
Trust Boundary: Self only
Potential Security Risks: IDOR on payment methods (other users' cards), unauthorized deletion
Notes: PCI DSS scope - critical if IDOR exists

---

Asset: Shopping Cart / Purchase
Feature: License purchase and renewal
Endpoint: /ShoppingCart/BuyFromStore, /ShoppingCart/RenewFromStore, /api/MidTermUpgrade/*, /api/ResumeOffer/*
HTTP Method: GET/POST
Authentication Required: Yes
User Role: Authenticated User
Important Parameters: productId, licenseId, paymentMethodId
Object Identifiers: licenseId, productId
Trust Boundary: Purchaser
Potential Security Risks: Price manipulation, cart IDOR, unauthorized renewal/upgrade
Notes: Business logic testing needed

---

## Safe Kids (Parental Control)

---

Asset: Safe Kids API
Feature: Child device monitoring and control
Endpoint: /MyKids/GlobalContext, /MyKids/AskForParentPermissionsContext, /SafeKids/api/Rules/UpdateSiteAccessSettings/childId, /ProductsSafeKids/DeviceUsageJson/*
HTTP Method: GET/POST
Authentication Required: Yes
User Role: Parent Account
Important Parameters: childId, deviceId
Object Identifiers: childId, deviceId
Trust Boundary: Parent → Child, cross-family
Potential Security Risks: IDOR on childId (access other families' children), unauthorized rule changes, location data leak
Notes: Child location data = high sensitivity PII

---

## SignalR / WebSocket

---

Asset: SignalR Hub
Feature: Real-time device status updates
Endpoint: /signalr/changes
HTTP Method: GET/POST (negotiate), WebSocket
Authentication Required: Yes (presumably)
User Role: Authenticated User
Important Parameters: connectionId
Object Identifiers: connectionId
Trust Boundary: User's own device stream
Potential Security Risks: CSHWS (cross-site WebSocket hijacking), unauthorized subscription to other users' device streams
Notes: Test WebSocket origin validation

---

## Information Disclosure Candidates

---

Asset: Error Logging
Feature: Client-side error logging
Endpoint: /Error/LogJsError
HTTP Method: POST
Authentication Required: No
User Role: Unauthenticated
Important Parameters: error data
Object Identifiers: N/A
Trust Boundary: None
Potential Security Risks: Log injection, sensitive data in errors
Notes: Client errors may leak internal paths

---

Asset: Translations
Feature: UI resource files
Endpoint: /Frontend/Resources/QebKWhvsxUO40QcAhfP1Sg/{set}/NextGen/{set}.en.json
HTTP Method: GET
Authentication Required: No
User Role: Unauthenticated
Important Parameters: translationsSet
Object Identifiers: N/A
Trust Boundary: None
Potential Security Risks: Info disclosure (low)
Notes: Portal version embedded in path

---

## Key Trust Boundaries Summary

```
Unauthenticated User
    ↓ (UIS auth: web.uis.kaspersky.com - OUT OF SCOPE)
Authenticated User (Master Account)
    ↓ (session cookies on my.kaspersky.com)
    ├── Own devices (/MyDevices/api/*)
    ├── Own licenses (/MyLicenses/*)
    ├── Own account settings (/MyAccountApi/*)
    ├── Own payment methods
    ↓ (family sharing - TRUST BOUNDARY)
Sub-Accounts / Children
    ↓ (cross-user - PRIMARY IDOR BOUNDARY)
Other Users' Devices/Licenses/Accounts
```

## Out-of-Scope Dependencies (DO NOT TEST)
- web.uis.kaspersky.com (UIS authentication)
- auth.uis.kaspersky.com (UIS logout)
- support.kaspersky.com (support portal redirect)
- shop.*.kaspersky.com (regional shops - CSP frame-src)
- kpcwebportalfilestorage.blob.core.windows.net (file storage - CSP img-src)
- Direct payment providers (nexway, etc.)
- Google reCAPTCHA, hCaptcha, Cookiebot, Yandex Metrika
- ksos.kaspersky.com (corporate portal)
