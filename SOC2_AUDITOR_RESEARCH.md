# SOC 2 Type II Auditor Research & Recommendations (Pre-Seed)

**Version:** 2.0 (Pre-Seed)
**Last Updated:** December 31, 2025
**Owner:** Founder

---

## Executive Summary

**Key Takeaway for Pre-Seed:** SOC 2 Type II is important but NOT a priority for pre-seed funding. Focus on product-market fit and first 100 customers first. Plan for SOC2 certification in Year 2-3 after achieving $500K-$1M ARR and 18+ months post-funding.

**Realistic Timeline for Pre-Seed Company:**
- **Months 1-12:** Focus on product validation, first revenue
- **Months 13-18:** Readiness assessment when you hit $500K ARR
- **Months 19-30:** Observation period + audit (when customers start asking for SOC2)
- **Month 30+:** SOC 2 Type II certified

**Realistic Budget:**
- **Pre-Seed (Year 1):** $5K-$10K (self-assessment, policy templates, readiness prep)
- **Seed/Series A (Year 2):** $40K-$60K (audit + automation platform)

**Why Wait:**
1. SOC2 costs $80K-$150K all-in—too much burn for pre-seed
2. Early customers (freelancers, consultancies) won't ask for SOC2
3. Investors care about traction (users, revenue), not compliance certifications pre-Series A
4. You can start preparing (policies, controls) for free while building revenue

---

## 1. What is SOC 2 Type II?

SOC 2 Type II is an attestation by an independent CPA firm that your internal controls operated effectively over a defined period (typically 3-12 months). It evaluates how your organization protects customer data against the **Trust Services Criteria (TSC)**:

- **Security** (mandatory): Access controls, encryption, monitoring, incident response
- **Availability** (optional): Uptime, disaster recovery, business continuity
- **Processing Integrity** (optional): Data processing accuracy, error handling
- **Confidentiality** (optional): NDA, data classification, access restrictions
- **Privacy** (optional): GDPR, CCPA compliance, data subject rights

**For Pre-Seed HeroForge:** Security only (simplest, cheapest). Add Availability when enterprise customers demand it (Year 2+).

---

## 2. When Do You ACTUALLY Need SOC 2?

### Reality Check: Most Pre-Seed Companies Don't Need SOC2

**Who asks for SOC2:**
- ✅ Enterprise customers (Fortune 500)
- ✅ Regulated industries (finance, healthcare)
- ✅ Government contractors

**Who doesn't ask for SOC2:**
- ❌ Freelance pentesters (your Month 1-6 customers)
- ❌ Small consultancies (your Month 6-12 customers)
- ❌ Security researchers
- ❌ Early adopters who trust the founder story

### When to Start SOC2 Process

**Trigger events:**
1. A paying customer explicitly asks for SOC2 report
2. You're pursuing enterprise deals ($50K+ ACV)
3. You hit $500K-$1M ARR and plan to raise Series A
4. Investors mention it as a requirement for next round

**Until then:** Self-assess, document policies, build foundational controls—but don't spend $80K on an audit.

---

## 3. Pre-Seed Timeline (Realistic)

### Year 1: Self-Assessment & Preparation ($5K-$10K)

**Months 1-6: Product Validation**
- [ ] Focus 100% on product-market fit
- [ ] Get first 100 paying customers
- [ ] Ignore SOC2 entirely

**Months 7-12: Readiness Prep (DIY)**
- [ ] Read SOC2 requirements (free resources)
- [ ] Download policy templates (SANS, NIST)
- [ ] Implement basic controls:
  - MFA on all admin accounts (AWS, GitHub, production)
  - CloudTrail logging enabled
  - Quarterly access reviews (spreadsheet is fine)
  - Incident response plan (1-page doc)
  - Vendor risk assessments (spreadsheet)
- [ ] Cost: $0 (your time) or $5K-$10K (hire consultant for 1-week gap analysis)

### Year 2: Observation Period + Audit ($40K-$60K)

**Months 13-18: Automation Platform & Readiness**
- [ ] Purchase Vanta or Drata ($18K-$30K/year)
- [ ] Fix gaps identified in self-assessment
- [ ] Start observation period (controls must run for 3-6 months)
- [ ] Cost: $18K-$30K (automation platform)

**Months 19-24: Audit Execution**
- [ ] Engage auditor (Johanson Group or KirkpatrickPrice)
- [ ] 3-6 month observation period
- [ ] Audit execution (4-6 weeks)
- [ ] Report issuance (2-4 weeks)
- [ ] Cost: $20K-$35K (audit fees)

**Total Year 2 Cost:** $40K-$65K (automation + audit)

---

## 4. Recommended Auditors (Pre-Seed Budget)

### Option 1: Johanson Group LLP (Best for Pre-Seed)

**Why Johanson:**
- Lowest cost: $20K-$30K for Security-only Type II
- Fastest turnaround: 4-6 weeks from audit start to final report
- Startup-friendly: Works with companies <$1M ARR
- Vanta/Drata integration: Accepts automated evidence

**Pricing Estimate:** $20K-$25K for Security Type II

**When to Use:** Year 2, after you hit $500K ARR and have first enterprise customer asking for SOC2

**Contact:** [https://www.johansonllp.com](https://www.johansonllp.com)

---

### Option 2: KirkpatrickPrice (Slightly More Expensive)

**Why KirkpatrickPrice:**
- Mid-tier pricing: $25K-$35K for Security Type II
- Good reputation with VCs
- Online portal for evidence submission

**Pricing Estimate:** $25K-$30K for Security Type II

**When to Use:** Year 2-3, if investor or large customer requires "name brand" auditor

**Contact:** [https://kirkpatrickprice.com](https://kirkpatrickprice.com)

---

### Option 3: A-LIGN (Series A, Not Pre-Seed)

**Why Wait on A-LIGN:**
- Higher cost: $30K-$40K for Security Type II
- Better for Series A+ companies
- Overkill for pre-revenue or early-stage

**When to Use:** Series A (Year 3+), when you're closing $50K+ enterprise deals regularly

**Contact:** [https://www.a-lign.com](https://www.a-lign.com)

---

## 5. Automation Platform (Year 2+)

### Don't Buy Vanta/Drata in Year 1

**Reality:** Automation platforms cost $18K-$30K/year. That's 18-30% of a $500K pre-seed round. Wait until Year 2.

### When to Purchase (Year 2)

**Timing:** When you start the observation period (Months 13-18)

**Platform Recommendation: Drata** (cheaper than Vanta)
- **Cost:** $18K-$24K/year
- **Features:** SOC2 automation, evidence collection, integrations (AWS, GitHub, Slack)
- **Why Drata over Vanta:** 20-30% cheaper, same functionality for early-stage

**Alternative: Secureframe** (cheapest)
- **Cost:** $15K-$20K/year
- **Why:** Best for bootstrapped/capital-efficient startups

---

## 6. What to Do in Year 1 (Pre-Seed)

### Free/Low-Cost SOC2 Prep

**Goal:** Lay the foundation without spending $80K

**1. Read & Learn (Free)**
- SOC2 Academy free course
- Vanta blog (free SOC2 guides)
- AICPA SOC2 criteria (download for free)

**2. Implement Basic Controls (Free)**
- **Access Control:**
  - ✅ Enable MFA on AWS, GitHub, production database, email
  - ✅ Document who has access to what (spreadsheet)
  - ✅ Quarterly access reviews (set calendar reminder)

- **Logging:**
  - ✅ Enable AWS CloudTrail (logs API calls)
  - ✅ Enable GitHub audit log
  - ✅ Retain logs for 1 year minimum

- **Change Management:**
  - ✅ All code changes require pull request review (GitHub)
  - ✅ Production deployments documented in Slack/email

- **Vendor Management:**
  - ✅ List all critical vendors (AWS, GitHub, Stripe, SendGrid)
  - ✅ Download their SOC2 reports (most provide on request)

- **Incident Response:**
  - ✅ Write 1-page incident response plan
  - ✅ Define who responds to security incidents
  - ✅ Test once per year (tabletop exercise)

**3. Policy Templates (Free or $500)**
- **Free:** SANS policy templates, NIST resources
- **Paid ($500):** Buy policy pack from Vanta (one-time purchase, no subscription)

**Total Year 1 Cost:** $0-$2,000 (mostly your time)

---

## 7. Common Control Failures to Avoid

The 5 controls that most commonly fail in SOC 2 audits for startups:

1. **Multi-Factor Authentication (MFA):** Not enforced on all critical systems
   - **Fix:** Enable MFA on AWS, GitHub, production databases, Google Workspace

2. **Access Reviews:** No quarterly reviews to remove stale accounts
   - **Fix:** Set calendar reminder, review every 90 days, document in spreadsheet

3. **Deprovisioning:** Ex-employees retain access >24 hours after termination
   - **Fix:** Create offboarding checklist (revoke AWS, GitHub, Slack, email)

4. **Change Approvals:** Production changes deployed without approval/peer review
   - **Fix:** Require pull request review in GitHub (branch protection rules)

5. **Logging:** Insufficient audit logs (no CloudTrail, no application logs)
   - **Fix:** Enable CloudTrail, retain logs for 1+ year

**Action:** Fix these 5 controls in Year 1 (costs $0, takes 2-4 hours of work)

---

## 8. Budget Allocation (Pre-Seed vs Series A)

### Pre-Seed Reality (Year 1): $5K

| Item | Cost | Notes |
|------|------|-------|
| **Gap analysis consultant** | $5K | 1-week engagement, identify what you're missing |
| **Policy templates** | $500 | One-time purchase (or use free SANS templates) |
| **Tools/software** | $0 | Use free tiers (AWS free tier, GitHub free, etc.) |
| **Internal labor** | $0 | Founder's time (10-20 hours over 12 months) |
| **Total Year 1** | **$5K** | Just preparation, no audit |

### Series A Reality (Year 2): $50K

| Item | Cost | Notes |
|------|------|-------|
| **SOC 2 Type II Audit** | $25K | Johanson Group or KirkpatrickPrice |
| **Automation Platform** | $20K | Drata annual subscription |
| **Penetration Testing** | $5K | Annual external pentest (or use HeroForge internally for $0) |
| **Internal Labor** | $0 | Still founder-led (or hire GRC lead in Year 3) |
| **Total Year 2** | **$50K** | Full audit + automation |

---

## 9. What Investors Care About (Pre-Seed)

### Reality: VCs Don't Care About SOC2 at Pre-Seed

**What pre-seed investors care about:**
1. ✅ Product-market fit (do people use it?)
2. ✅ Traction (revenue, users, growth rate)
3. ✅ Founder story (20 years SIGINT = credibility)
4. ✅ Market opportunity (TAM, SAM, SOM)
5. ✅ Unit economics (CAC, LTV, payback period)

**What they don't care about:**
- ❌ SOC2 certification
- ❌ ISO 27001
- ❌ Compliance frameworks

### When SOC2 Matters to Investors

**Series A:** Investors will ask "Do you have SOC2 or are you working on it?"
- ✅ Acceptable answer: "We're SOC2-ready and will start the audit next quarter when customers ask for it."
- ❌ Bad answer: "We haven't thought about compliance yet."

**Pre-Seed:** Investors might ask, but won't disqualify you for not having it yet.
- ✅ Acceptable answer: "We're implementing SOC2 controls now. We'll pursue certification when we hit $500K ARR and have enterprise customers asking for it."

---

## 10. Immediate Next Steps (Pre-Seed)

### This Month (Free)

1. **Read SOC2 basics** (2 hours)
   - SOC2 Academy free course
   - Vanta blog on SOC2 prep

2. **Enable MFA** (30 minutes)
   - AWS root account
   - GitHub organization
   - Google Workspace admin

3. **Enable logging** (30 minutes)
   - AWS CloudTrail
   - GitHub audit log
   - Application logs (if not already)

4. **Document access** (1 hour)
   - Create spreadsheet: User, System, Role, Access Level
   - Will be useful for access reviews later

### Next Quarter ($500-$2K)

1. **Download policy templates** ($0-$500)
   - SANS policy templates (free)
   - Or buy from Vanta ($500 one-time)

2. **Write incident response plan** (2 hours)
   - 1-page doc: Who responds? How? Escalation?

3. **Conduct vendor risk assessment** (2 hours)
   - List critical vendors (AWS, GitHub, Stripe)
   - Download their SOC2 reports

4. **Optional: Gap analysis** ($5K)
   - Hire consultant for 1-week assessment
   - Identifies what you're missing

### Year 2 (When You Hit $500K ARR)

1. **Purchase automation platform** ($18K-$24K)
   - Drata (cheaper) or Vanta (more features)

2. **Start observation period** (3-6 months)
   - Demonstrate controls operate effectively

3. **Engage auditor** ($20K-$30K)
   - Johanson Group or KirkpatrickPrice

4. **Receive SOC 2 Type II report** (Month 24-30)

---

## 11. Alternative: Use HeroForge Internally

**Pro tip:** HeroForge already has many SOC2-relevant features:

- ✅ Vulnerability scanning (meets "vulnerability management" control)
- ✅ Compliance frameworks (PCI-DSS, HIPAA, SOC2 checklists built-in)
- ✅ Evidence collection (automated scan reports)
- ✅ Penetration testing (annual pentest requirement = self-test)

**Action:** When you start SOC2 prep in Year 2, use HeroForge to:
1. Scan your own infrastructure (dogfooding)
2. Generate SOC2 compliance report
3. Collect evidence for auditor
4. Save $5K-$10K on external pentest (do it yourself)

---

## Conclusion

### TL;DR for Pre-Seed

**Year 1: Don't spend $80K on SOC2. Spend $5K on readiness.**
- Implement basic controls (MFA, logging, access reviews)
- Download free policy templates
- Document your processes

**Year 2: Spend $50K on SOC2 when customers ask for it.**
- Purchase Drata ($20K/year)
- Engage Johanson Group ($25K)
- Get certified in Months 19-30

**Why This Works:**
- Pre-seed customers (freelancers, consultancies) don't ask for SOC2
- Pre-seed investors don't require SOC2
- Spending $80K in Year 1 is wasteful when you need that capital for product and GTM
- You can prepare incrementally for $0-$5K and be "audit-ready" when the time comes

**Investor Messaging (Pre-Seed):**
> "We're implementing SOC2 controls as we build. We'll pursue formal certification in Year 2 when we hit $500K ARR and have enterprise customers requesting it. In the meantime, we're using HeroForge to scan our own infrastructure and maintain security best practices."

**Investor Messaging (Series A):**
> "We're SOC2-ready and starting the observation period this quarter. We expect to receive our Type II report in Q3. We've been operating under SOC2 controls for 18 months, so the audit will be straightforward."

---

**Document Owner:** Founder
**Review Cadence:** Quarterly (Year 1), Monthly (when pursuing SOC2 in Year 2)
**Last Updated:** December 31, 2025

**Related Documents:**
- [Pre-Seed Investor Strategy](./INVESTOR_STRATEGY_2025.md)
- [Pre-Seed GTM Execution Playbook](./GTM_EXECUTION_PLAYBOOK.md)

---

## Sources & References

- [How Much Does SOC 2 Compliance Cost in 2025?](https://sprinto.com/blog/soc-2-compliance-cost/)
- [SOC 2 Certification 2025: Auditor, Cost & Timeline Guide](https://www.dsalta.com/resources/articles/soc-2-certification-2025-auditor-cost-timeline-guide)
- [SOC 2 Budget: How Much Does SOC 2 Cost in 2025?](https://www.strongdm.com/blog/how-much-does-soc-2-cost)
- [Best SOC 2 Auditors and Companies in 2025](https://www.getastra.com/blog/security-audit/soc-2-auditors/)
- [Johanson Group SOC 2 Compliance](https://www.johansonllp.com/soc-2-assessment)
- [KirkpatrickPrice SOC 2 Audit Services](https://kirkpatrickprice.com/audit/soc-2/)

**Last updated:** December 31, 2025
**Version:** 2.0 (Pre-Seed)
