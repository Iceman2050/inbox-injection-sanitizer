# inbox-injection-sanitizer

**Your AI email summarizer may be reading instructions you can't see.**

On 2026-10-07, Barracuda documented live phishing that pairs a normal human lure with **hidden instructions targeting AI email summarizers** — pushing fake vendor payment changes (Barracuda Threat Spotlight). The human sees a routine email; the AI sees orders.

`inbox-injection-sanitizer` is a deterministic strip-and-surface CLI. It finds:
- **HTML comments** (`<!-- ... -->`) — the classic hidden-instruction carrier
- **Zero-width / invisible Unicode** (\u200b–\u200d, \ufeff, …)
- **Base64 blobs** — decoded and shown; instructional ones are stripped
- **CSS-hidden text** (`display:none`, `visibility:hidden`, `font-size:0`, tiny fonts)

Output: the clean text your summarizer should see, plus every surfaced item flagged instructional or not.

## What it does NOT do
It's not a phishing classifier and doesn't judge intent — it surfaces hidden machine-readable content deterministically. A clean report means "no hidden content detected", never "this email is safe".

## Usage
```
python -m inbox_injection_sanitizer suspicious-email.txt
# or: cat email.txt | python -m inbox_injection_sanitizer
```

## Built by Ingenious AI

This tool is built and maintained by **Ingenious AI**. Get early access to our AI security platforms:

- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI

