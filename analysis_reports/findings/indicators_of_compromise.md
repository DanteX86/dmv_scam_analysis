# Indicators of Compromise (IOCs)
## DMV Impersonation Scam Campaign

### Phone Numbers
- **+639127911810** (Primary threat actor number)
  - Carrier: Globe Telecom (Philippines)
  - Country: Philippines (+63)
  - Classification: High confidence malicious

### Domains
- **pa.gov-jad.vip** (Primary fraudulent domain)
  - Status: Offline (likely law enforcement action)
  - Impersonation Target: Pennsylvania government
  - TLD: .vip (premium domain)
  - Classification: Confirmed malicious

### Content Patterns
- Government impersonation keywords:
  - "DMV" OR "Department of Motor Vehicles"
  - "license.*suspend" OR "violation.*notice"
  - "government.*notice" OR "official.*notice"
  - "penalty.*avoid" OR "immediate.*action"

- Financial threat indicators:
  - "payment.*required" OR "pay.*immediately"
  - "urgent.*payment" OR "overdue.*payment"
  - "fine.*notice" OR "penalty.*fee"

### Behavioral Indicators
- SMS messages from international numbers claiming to be US government
- Urgent payment requests with tight deadlines
- Redirection to non-.gov websites for "official" business
- Business hours targeting (9 AM - 5 PM EST)

### Risk Assessment
- **Phone Number +639127911810**: CRITICAL - Block immediately
- **Domain pa.gov-jad.vip**: HIGH - Monitor for similar patterns
- **Content Patterns**: MEDIUM - Use for automated detection
- **Behavioral Patterns**: LOW - Context-dependent evaluation
