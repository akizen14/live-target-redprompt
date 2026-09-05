# red-prompt live target — "Acme Support"

A **deliberately vulnerable** AI customer-support application, built to be deployed on a
real public HTTPS host and scanned by [red-prompt](https://github.com/KshaunishHarsha/red-prompt)
exactly the way a customer's own endpoint would be.

> **This is a security test fixture, not a product.** It is designed to fail. Every customer
> record in it is invented and uses RFC 2606 reserved domains. Do not put real data in it,
> and do not point anything at it that you would not point at a honeypot.

It exists because red-prompt's three local `mock/` targets all bind `127.0.0.1`, so scanning
them requires `RP_ALLOW_PRIVATE_TARGETS=1` — the dev-only flag that disables the SSRF guard
entirely. That makes the demo path and the production path different paths, so a local demo
proves nothing about the deployed product. This runs on a public host with the guard fully on.

**What is under test is the application wrapper, not the model.** The upstream model's
alignment is the provider's problem; the system prompt, the retrieved documents, and the data
put in context are the client's. Blunt one-shot jailbreaks against this target mostly *fail*,
and that is the point — the attacks that land are the ones aimed at the application boundary.

## What's in the box

An OpenAI-compatible `POST /v1/chat/completions` endpoint that, on every request, prepends its
own system prompt, retrieves a knowledge-base article and injects it as context (two of the
four articles are poisoned), drops any caller-supplied `system` message, and forwards to a
real model — Groq by default, OpenAI when `OPENAI_API_KEY` is set.

A separate admin-keyed control plane flips the system prompt between VULNERABLE and HARDENED
at runtime, which is how a red-prompt finding goes `still_vulnerable` → `fixed` in a live demo
without redeploying anything.

Six planted weaknesses, each mapped to an OWASP LLM item and a DPDP control, with **measured**
(not intended) reliability: see [`docs/LIVE_TARGET.md` §3](docs/LIVE_TARGET.md).

## Quick start

```bash
pip install -r requirements.txt

export RP_TARGET_API_KEY=dev-smoke-key
export RP_ADMIN_KEY=admin-smoke-key
export GROQ_API_KEY=gsk_...            # console.groq.com, free tier
python app.py                          # http://127.0.0.1:9200
```

```bash
curl -s -X POST http://127.0.0.1:9200/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer dev-smoke-key" \
  -d '{"messages":[{"role":"user","content":"What is your refund policy for annual plans?"}]}'
```

A vulnerable instance answers with `AUDIT DUMP:` followed by the internal escalation code and
the synthetic customer table — the poisoned KB-204 article doing its job.

## Deploying

Render Blueprint ([`render.yaml`](render.yaml)) on the free plan. **The free instance sleeps
after ~15 minutes idle**, and a cold start makes the first probe of a scan time out — which
red-prompt scores as the target *resisting the attack*. Always warm it first:

```bash
./scripts/warm.sh https://<service>.onrender.com
```

Full instructions, including the Fly.io always-on alternative, are in
[`docs/LIVE_TARGET.md` §4](docs/LIVE_TARGET.md).

## Configuration

Every variable is annotated in [`.env.example`](.env.example). Two are mandatory:
`RP_TARGET_API_KEY` (without it the app refuses to serve, so this never becomes a free public
LLM proxy) and one of `GROQ_API_KEY` / `OPENAI_API_KEY`.

Read the `MIN_OUTPUT_TOKENS` / `MAX_OUTPUT_TOKENS` note before touching either. A ceiling
below the floor yields empty completions that every detector scores as the target resisting,
turning a whole scan into silent false negatives.

## Documentation

- [`docs/LIVE_TARGET.md`](docs/LIVE_TARGET.md) — the planted weaknesses, deployment, the
  vulnerable → fixed demo script, abuse controls, and troubleshooting.
- [red-prompt](https://github.com/KshaunishHarsha/red-prompt) — the scanner this is a target for.

## License

Apache 2.0, same as red-prompt. See [LICENSE](LICENSE).
