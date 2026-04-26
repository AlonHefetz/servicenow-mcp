# Let's Do This — Response to Chris

**From:** Nick Zitzer
**Date:** March 2026

---

Hey Chris —

First, totally hear you on the package names. You've put in the work to get those published, cleaned up, and stable on npm — the last thing we should do is break that for people who already depend on them. That's not on the table, full stop. Your packages keep their names, your npm scope stays as-is. No disruption to anyone already using `@sonisoft/now-sdk-ext-*`.

Same goes for mine — `servicenow-mcp-server` stays published and available where it is.

And honestly, re-reading my initial proposal I think I got ahead of myself on the restructuring side. You're right to push back on that. Let me recalibrate.

---

## What I Think Actually Makes Sense

### Shared Org — Your SNOS Idea Is Great

I love the SNOS-Coalition concept (or just SNOS). It's exactly the right framing: a community org for ServiceNow open-source work, not a rebrand of either of our existing projects.

**What the org would be:**
- A shared GitHub home — `github.com/snos-coalition/` (or `github.com/sn-os/`, whatever feels right)
- Both of us as Owners/maintainers
- A place for collaborative work that builds on what we've each already shipped

**What the org would NOT be:**
- A rename of your packages
- A migration that breaks anyone's existing installs
- A requirement that either of us stops maintaining our own repos

### How the Repos Could Work

I think the simplest path is:

**Option A: Fork into the org (preserve originals)**
Your repos stay exactly where they are under `sonisoft-cnanda/`. Mine stays under my account. We fork the relevant ones into the SNOS org as the "collaborative edition" — a place where we merge the best of both, experiment with consolidation, and ship new features together. Your originals remain the stable, published packages. The org fork becomes the next-gen version when it's ready.

**Option B: Transfer repos, keep names (your suggestion)**
Move the repos into the org with their original names intact. npm packages don't change — `@sonisoft/now-sdk-ext-core` still resolves, still installs, nothing breaks. The only thing that changes is the GitHub URL, and GitHub handles redirects automatically. This is cleaner if we're both comfortable with it.

Either way, the principle is: **nothing breaks for existing users.**

---

## Where I Think We Build Together

Rather than restructuring what exists, I think the highest-value work is combining our strengths into something neither of us has alone. Here's what I'd focus on:

### 1. Tool Consolidation (New Collaborative Work)

This is where I think the real win is, and it doesn't require renaming anything. Between us we have 90+ MCP tools. The research from Anthropic, Block, and Microsoft is clear that this hurts AI performance — sweet spot is 12-15 tools per server. I laid out a consolidation strategy in my earlier doc that I think is worth discussing on a call, but the short version:

- Fewer tools with richer parameters (one `SN-Query` instead of 8 table-specific list tools)
- Metadata-driven behavior so tools work on any table without per-table code
- Anthropic's `defer_loading` for specialist tools

This would be net-new work in the SNOS org, built on your core library, incorporating my metadata patterns. Not a replacement of either existing server — a next-gen version.

### 2. Cross-Pollinate Unique Features

Some things I've built that your server doesn't have yet (and vice versa) that would be straightforward to bring over:

**From mine → into yours (or the shared project):**
- Natural language query parser (15+ patterns, table-aware state mappings)
- SSE/HTTP transport (for Docker and hosted deployments)
- MCP Resources (8 read-only URIs for ambient AI context)
- sys_trigger background execution method
- Metadata-driven table definitions (94 tables, extraction scripts, runtime fallback)

**From yours → into mine (or the shared project):**
- Flow Designer integration (11 tools — huge gap in my server)
- ATF test execution (critical for CI/CD)
- WebSocket/AMB real-time events
- Aggregation queries (Stats API)
- Knowledge, Catalog, and App Management tools
- CMDB graph traversal
- Instance health monitoring

### 3. Documentation & Community Building

This is honestly where I think the ServiceNow ecosystem needs the most help, and where a shared org gives us leverage. I've got 40+ guides, research docs, and troubleshooting content. A docs site under the SNOS org — covering both our tools plus general ServiceNow MCP development patterns — could become the go-to resource for the community.

---

## The Bigger Picture (Why I Care)

I'll keep this brief since you said you don't care much about the marketing side, but I want you to know what's driving me beyond the code.

The ServiceNow developer community has been underserved for years. The platform itself is powerful, but the ecosystem around it has been starved while ServiceNow focuses on sales and enterprise licensing. Every other major enterprise platform has thriving open-source tooling. ServiceNow's is barely getting started.

I think open-source, community-built tools — like what we're both already doing — are how that changes. Not waiting for ServiceNow to prioritize developers, but just building the things developers need and putting them out there. The SNOS org could be a home for that kind of work, and not just from us — it's an open door for anyone in the community who wants to contribute.

That's the flag I want to plant. The code is the vehicle, but the point is: ServiceNow developers deserve better, and we can build it.

---

## Practical Next Steps

1. **A quick call** — 30 minutes to align on the org name, repo structure (Option A vs B), and what we want to build first
2. **Create the GitHub org** — both as Owners, minimal governance to start
3. **Pick a first project** — I'd suggest the consolidated MCP server as the flagship, but open to your thinking
4. **Keep shipping our own stuff** — none of this blocks either of us from continuing to maintain and publish what we've already built

No rush on any of this. You just finished a cleanup cycle and I respect that you want to protect the stability of what you've shipped. Whenever you're ready to hop on a call, I'm in.

**— Nick**
