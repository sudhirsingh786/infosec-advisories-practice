# How priority and fix deadlines are set

Priority and due dates are calculated in ServiceNow, not by hand. InfoSec sets the CVE **severity** and whether it is **exploited** (CISA KEV list or vendor confirmation). Your answers on the Confluence product line page set the **exposure** of your ServiceNow child ticket. The first matching rule wins.

| # | When | Priority | Fix within |
|---|---|---|---|
| 1 | Critical **and** (exploited **or** internet-facing) | P1 | 72 hours |
| 2 | Critical, all other cases | P2 | 15 days |
| 3 | High | P3 | 30 days |
| 4 | Medium | P4 | 90 days |
| 5 | Low | P5 | 180 days |

- A product line that has not answered is treated as internal, so a Critical CVE still runs on the P2 timer.
- Proposed, pending approval: customer-deployed releases count as internet-facing, and High + exploited or customer-deployed becomes P2.
- Ways to close a ticket: Remediated (verified by rescan), Mitigated (compensating control), Risk accepted (approved exception with expiry date), False positive, Asset decommissioned.
- Per-product priorities and customer impact are tracked in ServiceNow and Confluence, not on this site.
