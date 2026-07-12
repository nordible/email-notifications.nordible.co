# Stalwart Mail Server & WebUI Test Plan

This document lists the critical features in this repository to test both locally and on the production server (`150.241.247.99`).

## 1. Branding & Whitelabelling (Logo Fixes)
- [x] **First-stage Login Logo**: Visit the OAuth2/OIDC login page (`/account/login` or via the webmail redirect) and verify that the logo is loaded correctly on the username input step.
- [x] **Admin Login Logo**: Visit the admin interface login page (`/admin/login`) and verify the logo resolves to `logo.png` (or `/logo` if custom).
- [x] **Local Verification**: Verify `http://localhost:8080/admin/logo.png` returns the PNG image (83 KB) rather than falling back to `text/html`.
- [x] **Production Verification**: Verify `https://mailadmin.nordible.co/admin/logo.png` also returns the image correctly.


## 2. Authentication & Admin Panel
- [ ] **Admin Authentication**: Log in to the administrator portal (`/admin`) using admin credentials.
- [ ] **Domain Management**: Verify you can view, add, or edit mail domains.
- [ ] **User Provisioning**: Create a test user mailbox and configure their quota, password, and permissions.
- [ ] **OAuth2/OIDC Flows**: Initiate a login from the Webmail interface (`mailv1.nordible.co`) and verify the redirection to the OIDC login screen and back works seamlessly.

## 3. Webmail & JMAP / IMAP / SMTP Protocols
- [ ] **CORS Preflight (OPTIONS)**: Verify that requests from the Webmail container (`mailv1.nordible.co`) to Stalwart (`mailadmin.nordible.co`) do not trigger CORS errors on CORS preflight.
- [ ] **Inbound Mail**: Send a test email from an external provider (e.g., Gmail) to a user account on your domain and verify it is received.
- [ ] **Outbound Mail**: Send an email from your WebUI / Webmail to an external provider and verify delivery.
- [ ] **JMAP Synchronization**: Verify that folders, messages, and read/unread flags sync instantly via the JMAP protocol.

## 4. Reverse Proxy & Network (Caddy)
- [ ] **SSL/TLS Certificates**: Verify HTTPS works on both `mailv1.nordible.co` and `mailadmin.nordible.co` without SSL warnings.
- [ ] **Port Bindings**: Verify standard mail ports (`25`, `465`, `587`, `993`, `995`, `143`, `110`) are open and reachable on the production server.
