# HeroForge Go-to-Market Execution Playbook

**Version:** 1.0
**Last Updated:** December 30, 2025
**Owner:** CEO / Head of Growth

---

## Quick Reference: 90-Day Sprint Plan

| Week | Focus | Key Deliverables | Success Metrics |
|------|-------|------------------|-----------------|
| **1-2** | Foundation | Investor deck, financial model, SOC2 kickoff | Deck complete, audit engaged |
| **3-4** | Content Engine | 10 blog posts, 5 YouTube videos, Reddit presence | 1,000+ organic visitors |
| **5-6** | Freemium Funnel | Optimize trial signup, onboard 1st ISR | 50 trial signups/week |
| **7-8** | Paid Acquisition | LinkedIn ads, Google ads, track CAC | $500 CAC for Professional tier |
| **9-10** | MSP Partnerships | Identify 10 MSP partners, co-marketing materials | 3 signed partnership agreements |
| **11-12** | Enterprise PoC | Close 1st Enterprise deal, refine sales process | $50K+ ACV closed |

---

## 1. Customer Acquisition Channels (Prioritized)

### Channel #1: Content Marketing + SEO (Freemium Funnel)

**Target:** Freelance pentesters, small consultancies
**Cost:** $2K/month (freelance writers + tools)
**Timeline:** Months 1-6 (ongoing)

**Execution:**

1. **Blog (2x per week)**
   - Topics: "How to automate pentest reporting", "SOC2 compliance for consultancies", "AI in pentesting 2025"
   - SEO keywords: "pentesting software", "vulnerability management for consultancies", "automated security testing"
   - Tools: Ahrefs ($99/mo), Clearscope ($170/mo)

2. **YouTube (1x per week)**
   - Tutorials: HeroForge features, pentesting techniques, customer success stories
   - Format: 5-10 min videos, screen recordings + talking head
   - Growth: Optimize titles/thumbnails, CTAs to free trial

3. **Reddit/Hacker News**
   - Communities: r/netsec, r/AskNetsec, r/cybersecurity
   - Frequency: 2x per week (valuable content, not spam)
   - Strategy: Answer questions, share blog posts, AMA sessions

**KPIs:**
- 5,000 monthly blog visitors (Month 6)
- 1,000 YouTube subscribers (Month 6)
- 20% trial signup conversion from organic traffic

---

### Channel #2: Paid Acquisition (LinkedIn + Google Ads)

**Target:** Professional tier (security consultancies)
**Cost:** $10K/month ad spend
**Timeline:** Months 3-12

**Execution:**

1. **LinkedIn Ads**
   - Targeting: Job titles ("penetration tester", "security consultant", "CISO"), company size (2-50 employees)
   - Ad types: Sponsored content (blog posts), lead gen forms (free trial), video ads (product demo)
   - Budget: $5K/month
   - Expected CPC: $8-12
   - Expected conversion: 5% (trial signup) → 20% (paid)

2. **Google Ads**
   - Keywords: "pentesting software", "vulnerability management tool", "security testing platform"
   - Ad copy: "50-70% cheaper than Tenable. 14-day free trial. No credit card required."
   - Landing pages: Dedicated for each keyword cluster (customize messaging)
   - Budget: $5K/month
   - Expected CPC: $15-25
   - Expected conversion: 8% (trial signup) → 20% (paid)

**KPIs:**
- $500 CAC (all-in: ad spend + trial nurturing)
- 50 Professional tier signups/month (Month 6)
- 3:1 LTV:CAC ratio minimum

---

### Channel #3: MSP Partnership Program

**Target:** Team tier (MSPs with 10+ clients)
**Cost:** $3K/month (partner manager time + co-marketing)
**Timeline:** Months 5-12

**Execution:**

1. **Partner Identification**
   - Sources: CompTIA member list, ASCII Group, Datto/ConnectWise partner directories
   - Criteria: 10-50 employees, 50+ clients, existing security practice
   - Outreach: Email + LinkedIn (warm intro via existing customers if possible)

2. **Partner Program Structure**
   - **Tier 1 (Reseller):** 20% recurring commission, co-branded materials, joint webinars
   - **Tier 2 (Referral):** 10% one-time commission, access to customer portal demo
   - **Benefits:** Dedicated Slack channel, monthly product roadmap updates, priority support

3. **Co-Marketing**
   - Joint webinars: "How to Add Pentesting to Your MSP Stack" (partner presents with us)
   - Case studies: Feature partner's client success (anonymized)
   - Sales enablement: Provide battle cards, ROI calculators, demo scripts

**KPIs:**
- 10 active partners by Month 12
- 30 customer referrals from partners (Month 12)
- $3,000 CAC (partner-sourced deals)

---

### Channel #4: Enterprise Outbound Sales

**Target:** Enterprise tier (Fortune 2000 CISOs)
**Cost:** $200K/year (2x field AEs + SE support)
**Timeline:** Months 7-24

**Execution:**

1. **Account-Based Marketing (ABM)**
   - Target accounts: 100 Fortune 2000 companies (prioritize regulated industries: finance, healthcare, retail)
   - Research: Use LinkedIn Sales Navigator, ZoomInfo for contact discovery
   - Outreach cadence: 7-touch sequence (email, LinkedIn, phone, video)

2. **Proof of Concept (PoC) Process**
   - Duration: 30 days
   - Scope: Network scan (500 hosts), web app scan (5 apps), compliance report (SOC2)
   - Success criteria: Find 10+ high-severity vulnerabilities, deliver executive dashboard
   - Pricing: Free PoC (loss leader to close $50K+ annual deal)

3. **Sales Cycle**
   - Average: 90-120 days
   - Stages: Outreach → Discovery → PoC → Proposal → Negotiation → Close
   - Close rate: 20% (1 in 5 PoCs convert to paid)

**KPIs:**
- 10 Enterprise deals closed (Year 1)
- $50K average contract value (ACV)
- $25K CAC (all-in: sales salaries, SE support, travel)

---

## 2. Pricing & Packaging Strategy

### Tier Optimization

| Tier | Current Price | Proposed Change | Rationale |
|------|---------------|-----------------|-----------|
| **Solo** | $99/month | No change | Freemium anchor, low friction |
| **Professional** | $299/month | Test $349/month | 17% increase, still 60% cheaper than Rapid7 ($175/mo per app) |
| **Team** | $599/month | No change | Sweet spot for MSPs, good value perception |
| **Enterprise** | Custom | Standardize at $5K/mo base | Simplify sales process, add usage-based pricing for >500 hosts |

### Feature Gating

**Solo Tier (Stay Freemium-Friendly):**
- Keep: Unlimited network scans, basic reports (JSON, CSV, Markdown)
- Remove: PDF/HTML reports (upsell to Professional)
- Add: 3-scan history limit (delete older scans to force upgrades)

**Professional Tier (Emphasize Collaboration):**
- Keep: Everything in Solo, plus: 5 users, scheduled scans, JIRA integration
- Add: Slack/Teams notifications (currently in Team tier → move to Professional)
- Upsell: Customer portal (Team tier exclusive)

**Team Tier (MSP Value Prop):**
- Keep: Customer portal (10 customers), CRM, time tracking
- Add: White-label branding (custom domain, logo)
- Upsell: Unlimited customer portals (Enterprise tier)

### Annual Prepay Incentive

- **Discount:** 15% off (11 months for the price of 12)
- **Cash flow:** Improve runway by collecting annual contracts upfront
- **Churn reduction:** Annual contracts have 50% lower churn vs monthly

---

## 3. Conversion Funnel Optimization

### Free Trial → Paid Conversion

**Current Baseline (Assumed):** 15% trial-to-paid conversion
**Target:** 25% by Month 6

**Tactics:**

1. **Email Nurture Sequence (14 days)**
   - Day 0: Welcome email + onboarding checklist
   - Day 1: Video tutorial (network scan)
   - Day 3: Feature spotlight (AI prioritization)
   - Day 5: Case study (freelancer success story)
   - Day 7: Webinar invite ("Master HeroForge in 30 Minutes")
   - Day 10: Competitive comparison (vs Tenable pricing)
   - Day 12: Urgency email ("Trial ends in 2 days")
   - Day 14: Discount offer (20% off first month)

2. **In-App Prompts**
   - After 1st scan: "Want PDF reports? Upgrade to Professional"
   - After 5 scans: "You're a power user! Save 15% with annual billing"
   - After adding 2nd user: "Unlock team collaboration with Professional tier"

3. **Sales-Assisted Conversion (High-Intent Users)**
   - Trigger: User runs >10 scans in trial period
   - Action: Inside sales rep reaches out via email + phone
   - Offer: Personalized demo, answer questions, offer discount

**KPIs:**
- 25% trial-to-paid conversion (Month 6)
- 10% upgrade rate from Solo → Professional (within 6 months)
- 5% upgrade rate from Professional → Team (within 12 months)

---

## 4. Customer Success & Retention

### Onboarding (First 30 Days)

**Goal:** Get users to "aha moment" (1st successful scan + actionable report) within 24 hours.

**Playbook:**

1. **Welcome Email (Day 0)**
   - Subject: "Your HeroForge account is ready 🚀"
   - Content: 3-step quick start (connect target, run scan, view report)
   - CTA: "Run your first scan now"

2. **In-App Tour (First Login)**
   - Highlight: Scan creation, AI prioritization dashboard, PDF export
   - Format: Interactive tooltips (use Appcues or Pendo)

3. **Week 1 Check-In (Day 7)**
   - Email from CEO: "How's your experience so far?"
   - Ask: What's your #1 pain point with current tools?
   - Offer: Book 15-min strategy call

**KPIs:**
- 80% of users run 1st scan within 24 hours
- 50% of users complete onboarding checklist (5 scans, 1 PDF export, 1 compliance report)

### Churn Reduction

**Current Churn (Assumed):** 15%/year (industry average: 20%)
**Target:** 10%/year by Month 12

**Tactics:**

1. **Proactive Outreach (Low-Usage Accounts)**
   - Trigger: User hasn't logged in for 14 days
   - Action: Email + phone call from customer success manager (CSM)
   - Offer: Training session, feature walkthrough, use case guidance

2. **Churn Survey (Exit Feedback)**
   - Question: "Why are you canceling?"
   - Options: Too expensive, missing features, switched to competitor, no longer needed
   - Follow-up: If "too expensive," offer 20% discount; if "missing features," schedule product feedback call

3. **Win-Back Campaign (Churned Customers)**
   - Timing: 60 days after cancellation
   - Message: "We've added [new feature you requested]. Come back and get 1 month free."
   - Target: 10% win-back rate

---

## 5. Sales Enablement

### Battle Cards

**vs Tenable:**
- **Price:** HeroForge $999/year vs Tenable $2,275/year (56% savings)
- **Unique:** Customer portal + CRM (Tenable doesn't have)
- **Weakness:** Tenable has stronger cloud security (AWS Inspector integration)
- **Objection handling:** "If you need cloud-specific features, we integrate with AWS Security Hub. For consultancy management, we're the only option."

**vs Qualys:**
- **Price:** Transparent pricing vs Qualys per-target fees
- **Unique:** AI prioritization (ML model, not just CVSS)
- **Weakness:** Qualys has broader vulnerability coverage (more plugins)
- **Objection handling:** "Our AI reduces false positives by 70%, so you spend less time triaging. Quality over quantity."

**vs Traditional Pentesting:**
- **Price:** $999/year vs $5K-$100K per engagement (96% savings)
- **Unique:** Continuous testing vs periodic assessments
- **Weakness:** Manual pentests find business logic flaws
- **Objection handling:** "Use HeroForge for continuous scanning, hire pentesters for annual deep dives. Hybrid approach = best ROI."

### ROI Calculator (Sales Tool)

**Inputs:**
- Current pentesting spend ($/year)
- Number of scans per year
- Pentester hourly rate ($/hour)
- Time spent on reporting (hours/scan)

**Outputs:**
- Annual savings with HeroForge
- ROI percentage
- Payback period (months)

**Example:**
- Consultancy spends $10K/year on Tenable + 200 hours/year on manual reporting ($20K labor @ $100/hour)
- HeroForge: $3,588/year (Professional tier) + 25 hours/year reporting ($2,500 labor)
- Savings: $24,000/year (80% reduction)
- Payback: 1.8 months

---

## 6. Metrics Dashboard (Weekly Review)

| Metric | Current | Target (Month 6) | Owner |
|--------|---------|------------------|-------|
| **Acquisition** |  |  |  |
| Website visitors | 1,000/mo | 10,000/mo | Marketing |
| Trial signups | 100/mo | 500/mo | Marketing |
| Trial-to-paid conversion | 15% | 25% | Product |
| **Revenue** |  |  |  |
| MRR | $83K | $150K | CEO |
| ARR | $1M | $1.8M | CEO |
| NRR (Net Revenue Retention) | 110% | 115% | CS |
| **Retention** |  |  |  |
| Monthly churn | 1.5% | 1.0% | CS |
| Annual churn | 15% | 10% | CS |
| **Unit Economics** |  |  |  |
| CAC (Customer Acquisition Cost) | $300 | $500 | Marketing |
| LTV (Lifetime Value) | $6,000 | $8,000 | Finance |
| LTV:CAC ratio | 20:1 | 16:1 | Finance |
| Payback period (months) | 3 | 5 | Finance |

---

## 7. Team Hiring Plan (12 Months)

| Role | Hire Date | Salary | Quota/Target |
|------|-----------|--------|--------------|
| **Inside Sales Rep (ISR)** | Month 2 | $60K base + $40K OTE | $50K/month new MRR |
| **Content Marketer** | Month 3 | $70K | 10K monthly blog visitors |
| **Customer Success Manager (CSM)** | Month 5 | $65K | <10% annual churn |
| **Field AE #1** | Month 7 | $80K base + $80K OTE | 2 Enterprise deals/quarter |
| **Sales Engineer (SE)** | Month 9 | $120K | Support 10 PoCs/month |
| **Field AE #2** | Month 10 | $80K base + $80K OTE | 2 Enterprise deals/quarter |
| **Marketing Manager** | Month 12 | $100K | Own full funnel (awareness → conversion) |

**Total Year 1 GTM Headcount:** 7 (1 ISR, 2 AEs, 1 SE, 1 CSM, 2 Marketing)

---

## 8. Budget Allocation (Series A Use of Funds - GTM Portion)

**Total GTM Budget:** $1.8M (30% of $6M raise)

| Category | Amount | % | Details |
|----------|--------|---|---------|
| **Sales Team** | $800K | 44% | 2 AEs ($160K), 1 SE ($120K), 1 ISR ($100K), 1 CSM ($65K), tools ($40K), travel ($15K) |
| **Marketing** | $600K | 33% | Content marketer ($70K), marketing manager ($100K), ads ($240K), tools/events ($190K) |
| **Partner Program** | $200K | 11% | Partner manager ($80K), co-marketing ($60K), commissions ($60K) |
| **Customer Success** | $200K | 11% | Onboarding tools ($50K), CSM software ($30K), training content ($120K) |

---

## 9. Key Risks & Mitigation

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **CAC too high (>$1,000)** | Medium | High | Double down on organic (SEO, YouTube), pause paid ads until conversion optimized |
| **Trial-to-paid conversion <15%** | Medium | High | Implement sales-assisted conversion for high-intent users, improve onboarding |
| **MSP partnerships don't scale** | Medium | Medium | Pivot to direct sales + referral program, offer higher commissions |
| **Churn >20%** | Low | Critical | Proactive CS outreach, feature velocity (ship requested features), price optimization |

---

## 10. Next Steps (Immediate Actions)

### This Week:
- [ ] Finalize investor deck (see INVESTOR_STRATEGY_2025.md)
- [ ] Launch investor page at /investors
- [ ] Draft 10 blog post outlines (content calendar)
- [ ] Hire freelance writer (Upwork, $50/article)

### Next 2 Weeks:
- [ ] Set up LinkedIn ads account, create first 3 ad campaigns
- [ ] Record 5 YouTube tutorials (product walkthroughs)
- [ ] Identify 20 target MSP partners (research phase)
- [ ] Onboard 1st inside sales rep (post job on LinkedIn, AngelList)

### Next 30 Days:
- [ ] Hit $100K MRR ($1.2M ARR run rate)
- [ ] 500 trial signups/month
- [ ] 3 MSP partnership agreements signed
- [ ] SOC2 audit kickoff (engage auditor)

---

**Document Owner:** CEO / Head of Growth
**Review Cadence:** Weekly (GTM metrics), Monthly (strategy adjustments)
**Last Updated:** December 30, 2025

**Related Documents:**
- [Investor Strategy 2025](./INVESTOR_STRATEGY_2025.md)
- [Market Evaluation 2025](./MARKET_EVALUATION_2025.md)
- [Feature Roadmap P2](./FEATURE_ROADMAP_P2.md)
