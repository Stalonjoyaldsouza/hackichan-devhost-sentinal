# Support bot (example business application)

A small customer-support agent used to demonstrate the Sentinel SDK. It answers customer
questions with an LLM, and the LLM can call tools to look up customers, issue refunds, email
customers, and run a shell-based report. **It is deliberately a bit unsafe** so the SDK has things
to find. Nothing here talks to a real service unless you supply credentials.
