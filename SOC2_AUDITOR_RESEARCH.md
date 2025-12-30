# SOC 2 Type II Auditor Research & Recommendations

**Version:** 1.0
**Last Updated:** December 30, 2025
**Owner:** CEO / Head of Compliance

---

## Executive Summary

SOC 2 Type II certification is a critical milestone for HeroForge's Series A fundraise and enterprise sales strategy. Based on current market research, we should expect:

- **Total Cost:** $80K-$150K (audit + automation + preparation)
- **Timeline:** 6-9 months (including 3-6 month observation period)
- **Internal Resources:** 0.5-1.0 FTE combined across Security, DevOps, and Engineering
- **Recommended Auditor:** A-LIGN or KirkpatrickPrice (startup-friendly, competitive pricing)
- **Automation Platform:** Vanta or Drata ($10K-$30K/year)

**Key Takeaway:** SOC 2 Type II is achievable within 9 months at a total cost of ~$100K, positioning HeroForge for enterprise deals and investor confidence.

---

## 1. What is SOC 2 Type II?

SOC 2 Type II is an attestation by an independent CPA firm that your internal controls operated effectively over a defined period (typically 3-12 months). It evaluates how your organization protects customer data against the **Trust Services Criteria (TSC)**:

- **Security** (mandatory): Access controls, encryption, monitoring, incident response
- **Availability** (optional): Uptime, disaster recovery, business continuity
- **Processing Integrity** (optional): Data processing accuracy, error handling
- **Confidentiality** (optional): NDA, data classification, access restrictions
- **Privacy** (optional): GDPR, CCPA compliance, data subject rights

**For HeroForge:** We should pursue **Security + Availability** to satisfy enterprise customer requirements for uptime and resilience.

---

## 2. Timeline

| Phase | Duration | Activities |
|-------|----------|------------|
| **Readiness Assessment** | 4-6 weeks | Gap analysis, control design, policy creation, automation platform setup |
| **Remediation & Preparation** | 8-12 weeks | Implement controls, automate evidence collection, fix gaps, train team |
| **Observation Period** | 3-6 months | Demonstrate consistent operation of controls (cannot be accelerated) |
| **Audit Execution** | 4-6 weeks | Auditor testing, evidence review, client interviews |
| **Report Issuance** | 2-4 weeks | Draft review, management responses, final SOC 2 report |

**Total Timeline:** 6-9 months from kickoff to final report.

**Critical Path:** The observation period (3-6 months) is the longest phase and cannot be shortened. Automation platforms like Vanta/Drata can reduce readiness time from 12 weeks to 6 weeks.

---

## 3. Cost Breakdown

### Audit Fees

| Audit Firm Tier | Type I Cost | Type II Cost | Notes |
|-----------------|-------------|--------------|-------|
| **Big 4 (Deloitte, EY, KPMG, PwC)** | $50K-$100K+ | $80K-$150K+ | Overkill for Series A startups, slow turnaround |
| **Mid-Tier (A-LIGN, KirkpatrickPrice)** | $15K-$25K | $25K-$50K | Best for startups, fast turnaround, competitive pricing |
| **Boutique Firms (Johanson Group)** | $12K-$20K | $20K-$35K | Great for small SaaS companies, 4-6 week report delivery |

**Recommended Budget for HeroForge:** $30K-$40K for Type II audit (Security + Availability).

### Total Compliance Costs (Year 1)

| Category | Estimated Cost | Notes |
|----------|----------------|-------|
| **Readiness Assessment** | $10K-$15K | Gap analysis, policy templates, control design (can use Vanta/Drata templates) |
| **Automation Platform** | $15K-$30K | Vanta ($24K/year) or Drata ($18K/year), first-year pricing |
| **Audit Fees (Type II)** | $30K-$40K | A-LIGN or KirkpatrickPrice |
| **Penetration Testing** | $5K-$10K | Annual pentest required for SOC 2 (we can use HeroForge internally!) |
| **Training & Legal** | $5K-$10K | Employee security training, legal review of policies |
| **Internal Labor** | $20K-$30K | 0.5 FTE @ $100K salary over 9 months |

**Total Year 1 Cost:** $85K-$135K (budget ~$100K conservatively)

---

## 4. Recommended Auditors

### Option 1: A-LIGN (Recommended)

**Overview:** Technology-enabled auditor, #1 issuer of SOC 2 reports, 5,700+ clients, 400+ auditors, 96% client satisfaction.

**Pros:**
- Startup-friendly: Specializes in SaaS companies
- Fast turnaround: 4-6 weeks for report after audit
- Competitive pricing: $25K-$40K for Type II
- Audit management platform: Online portal for evidence submission
- Bundled discounts: 10-15% off Type I + Type II combo

**Cons:**
- Mid-tier pricing (not cheapest, but fair value)
- Large client base may mean less personalized service

**Pricing Estimate:** $30K-$40K for Security + Availability Type II

**Contact:** [https://www.a-lign.com](https://www.a-lign.com)

---

### Option 2: KirkpatrickPrice

**Overview:** Licensed CPA firm with 18+ years of InfoSec experience, PCAOB-registered, serves 1,000+ clients globally.

**Pros:**
- Experienced with startups: Dedicated startup practice
- Online Audit Manager: Portal for evidence and communication
- Multi-service: SOC, ISO 27001, HIPAA, PCI (if we need bundled certifications)
- Onsite visits available: Can travel for client meetings if needed

**Cons:**
- Slightly higher pricing than boutique firms
- Longer audit cycles (8-10 weeks) vs. A-LIGN (4-6 weeks)

**Pricing Estimate:** $25K-$35K for Security + Availability Type II

**Contact:** [https://kirkpatrickprice.com](https://kirkpatrickprice.com)

---

### Option 3: Johanson Group LLP

**Overview:** Boutique firm specializing in SOC 2, ISO 27001, HIPAA, GDPR audits. Fast turnaround (4-6 weeks).

**Pros:**
- **Fastest turnaround:** 4-6 weeks from audit start to final report (industry-leading)
- **Lowest cost:** $20K-$30K for Type II
- Great fit for small SaaS startups
- Works well with Vanta/Drata automation platforms
- Excellent G2 reviews from startups

**Cons:**
- Smaller firm (may lack capacity during peak audit season)
- Less brand recognition vs. A-LIGN/KirkpatrickPrice

**Pricing Estimate:** $20K-$30K for Security + Availability Type II

**Contact:** [https://www.johansonllp.com](https://www.johansonllp.com)

---

## 5. Automation Platform Comparison

Automation platforms reduce manual evidence collection by 80% and cut readiness time in half.

| Platform | Annual Cost | Pros | Cons | Auditor Partnerships |
|----------|-------------|------|------|---------------------|
| **Vanta** | $24K-$36K | Market leader, best integrations (AWS, GitHub, Slack, etc.), SOC 2 + ISO 27001 + HIPAA | Most expensive | A-LIGN, Schellman, Johanson |
| **Drata** | $18K-$30K | Competitive pricing, good UI, SOC 2 + ISO 27001 + HIPAA | Fewer integrations than Vanta | KirkpatrickPrice, A-LIGN |
| **Secureframe** | $15K-$25K | Cheapest, fast setup, SOC 2 + ISO 27001 | Smaller customer base, fewer features | Johanson, smaller firms |

**Recommended:** **Vanta** (best ROI for enterprise sales, strong brand recognition with VCs and customers)

---

## 6. Common Control Failures (What to Fix First)

The 10 controls that most commonly fail in SOC 2 audits for startups:

1. **Multi-Factor Authentication (MFA):** Not enforced on all critical systems (AWS, GitHub, production databases)
2. **Access Reviews:** No quarterly access reviews to remove stale accounts
3. **Deprovisioning:** Ex-employees retain access >24 hours after termination
4. **Change Approvals:** Production changes deployed without approval/peer review
5. **Logging:** Insufficient audit logs (no CloudTrail, no application logs, no SIEM)
6. **Vulnerability SLAs:** No defined SLA for patching Critical (7 days) and High (30 days) vulnerabilities
7. **Backups:** No automated backups or restore testing
8. **DR Tests:** Disaster recovery plan not tested annually
9. **Incident Drills:** Incident response plan not tested quarterly
10. **Vendor Reviews:** No annual vendor risk assessments for critical vendors (AWS, GitHub, SendGrid)

**Action:** Prioritize automating these controls in the readiness phase (Vanta/Drata can automate 80% of these).

---

## 7. Preparation Checklist

### Phase 1: Readiness (Weeks 1-6)

- [ ] Select auditor (A-LIGN, KirkpatrickPrice, or Johanson)
- [ ] Purchase automation platform (Vanta or Drata)
- [ ] Conduct gap analysis (automated by Vanta/Drata)
- [ ] Create security policies (use Vanta templates)
- [ ] Define control objectives and procedures
- [ ] Assign control owners (Security, DevOps, Engineering leads)

### Phase 2: Remediation (Weeks 7-18)

- [ ] Implement MFA on all critical systems (AWS, GitHub, databases)
- [ ] Enable audit logging (CloudTrail, application logs, GitHub audit log)
- [ ] Set up SIEM or log aggregation (e.g., AWS CloudWatch, Datadog)
- [ ] Automate access reviews (quarterly via Vanta/Drata)
- [ ] Create deprovisioning runbook (offboarding checklist)
- [ ] Implement change approval process (GitHub pull request reviews)
- [ ] Define vulnerability SLAs (Critical: 7 days, High: 30 days, Medium: 90 days)
- [ ] Set up automated backups (database snapshots, code backups)
- [ ] Create disaster recovery plan and test it
- [ ] Create incident response plan and conduct tabletop drill
- [ ] Conduct vendor risk assessments (AWS, GitHub, SendGrid, etc.)
- [ ] Run penetration test (use HeroForge internally!)

### Phase 3: Observation (Months 4-9)

- [ ] Operate controls consistently for 3-6 months
- [ ] Collect evidence automatically via Vanta/Drata
- [ ] Conduct monthly control monitoring (access reviews, vuln scans)
- [ ] Document exceptions and remediation

### Phase 4: Audit (Weeks 1-6 after observation)

- [ ] Submit evidence to auditor
- [ ] Respond to auditor questions and requests
- [ ] Conduct employee interviews
- [ ] Review draft report and provide management responses
- [ ] Receive final SOC 2 Type II report

---

## 8. Budget Allocation (Series A Use of Funds)

From our $6M Series A raise, allocate **$200K** for compliance over 18 months:

| Item | Year 1 Cost | Year 2 Cost | Notes |
|------|-------------|-------------|-------|
| **SOC 2 Type II Audit** | $35K | $30K | Annual renewal (10% discount) |
| **Vanta Subscription** | $30K | $30K | Annual license |
| **Penetration Testing** | $10K | $10K | Annual external pentest (or use HeroForge internally for $0) |
| **Training & Legal** | $10K | $5K | Security awareness training, policy review |
| **Internal Labor (0.5 FTE)** | $25K | $15K | Security/GRC lead (half-time in Year 1, part-time in Year 2) |
| **ISO 27001 (optional)** | $0 | $40K | If needed for EU customers in Year 2 |

**Year 1 Total:** $110K (includes buffer)
**Year 2 Total:** $90K (renewal + maintenance)

---

## 9. Timeline for Series A Fundraise

Based on our GTM playbook (target close in Q1 2026), we should:

| Date | Milestone |
|------|-----------|
| **Week 1-2 (Jan 2026)** | Select auditor, sign engagement letter, purchase Vanta |
| **Weeks 3-6 (Feb 2026)** | Gap analysis, create policies, assign control owners |
| **Weeks 7-18 (Mar-May 2026)** | Implement controls, fix gaps, automate evidence collection |
| **Months 4-9 (Jun-Nov 2026)** | 6-month observation period |
| **Weeks 1-6 (Dec 2026)** | Audit execution and evidence review |
| **Jan 2027** | Receive SOC 2 Type II report |

**Investor Messaging:** "We have engaged [Auditor] for SOC 2 Type II certification, targeting completion by Q1 2027. Our readiness assessment shows strong control maturity, and we're using Vanta to automate 80% of evidence collection."

---

## 10. Immediate Next Steps

### This Week:
1. **Get quotes from 3 auditors:**
   - A-LIGN: https://www.a-lign.com/contact
   - KirkpatrickPrice: https://kirkpatrickprice.com/request-quote/
   - Johanson Group: https://www.johansonllp.com/contact

2. **Request Vanta demo:** https://www.vanta.com/demo

3. **Add to investor deck:** "SOC 2 Type II certification in progress, expected Q1 2027"

### Next 2 Weeks:
1. Sign auditor engagement letter (target A-LIGN or Johanson)
2. Purchase Vanta subscription
3. Kick off gap analysis
4. Assign Security/GRC lead (0.5 FTE, can hire or assign internally)

### Next 30 Days:
1. Complete readiness assessment
2. Create security policies (use Vanta templates)
3. Begin remediation work (MFA, logging, access reviews)
4. Add SOC 2 timeline to internal roadmap

---

## 11. Sources & References

Based on comprehensive research from industry-leading sources:

- [How Much Does SOC 2 Compliance Cost in 2025?](https://sprinto.com/blog/soc-2-compliance-cost/)
- [SOC 2 Certification 2025: Auditor, Cost & Timeline Guide](https://www.dsalta.com/resources/articles/soc-2-certification-2025-auditor-cost-timeline-guide)
- [SOC 2 Budget: How Much Does SOC 2 Cost in 2025?](https://www.strongdm.com/blog/how-much-does-soc-2-cost)
- [SOC 2 Audit Costs in 2025: Full Cost Breakdown](https://www.uprootsecurity.com/blog/how-much-does-a-soc-2-audit-cost)
- [Best SOC 2 Auditors and Companies in 2025](https://www.getastra.com/blog/security-audit/soc-2-auditors/)
- [13 Best SOC 2 Audit Firms in 2025](https://www.brightdefense.com/resources/soc-2-audit-firms/)
- [A-LIGN SOC 2 Services](https://www.a-lign.com/service/soc-2)
- [KirkpatrickPrice SOC 2 Audit Services](https://kirkpatrickprice.com/audit/soc-2/)
- [Johanson Group SOC 2 Compliance](https://www.johansonllp.com/soc-2-assessment)

---

**Document Owner:** CEO / Head of Compliance
**Review Cadence:** Monthly (during SOC 2 preparation), Annually (post-certification)
**Last Updated:** December 30, 2025

**Related Documents:**
- [Investor Strategy 2025](./INVESTOR_STRATEGY_2025.md)
- [GTM Execution Playbook](./GTM_EXECUTION_PLAYBOOK.md)
- [Feature Roadmap P2](./FEATURE_ROADMAP_P2.md)
