import { PrismaClient } from "@prisma/client";
import { randomUUID } from "crypto";

const prisma = new PrismaClient();

const AGENTS = ["support-bot-1", "data-pipeline-3", "email-agent", "code-assistant", "onboarding-bot"];
const RULES = ["pii_detection", "financial_limit", "prompt_injection", "tone_sentiment", "rate_limit"];

function randomChoice<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomFloat(min: number, max: number): number {
  return Math.round((Math.random() * (max - min) + min) * 10) / 10;
}

function generateEvents(count: number) {
  const events = [];
  const now = Date.now();
  const sevenDays = 7 * 24 * 60 * 60 * 1000;

  for (let i = 0; i < count; i++) {
    const timestamp = new Date(now - Math.random() * sevenDays);
    const rand = Math.random();

    // 60% approved, 30% blocked, 10% error
    let status: string, rule: string | null, reason: string | null, details: any;

    if (rand < 0.6) {
      status = "approved";
      rule = null;
      reason = null;
      details = null;
    } else if (rand < 0.9) {
      status = "blocked";
      rule = randomChoice(RULES);

      switch (rule) {
        case "pii_detection":
          reason = randomChoice([
            "PII detected: ssn in field 'body'",
            "PII detected: credit_card in field 'message'",
            "PII detected: email in field 'content'",
            "PII detected: phone in field 'body'",
          ]);
          details = {
            type: randomChoice(["ssn", "credit_card", "email", "phone"]),
            matched: ["***-**-****"],
            field: randomChoice(["body", "message", "content"]),
          };
          break;
        case "financial_limit":
          const amount = Math.round(Math.random() * 50000 + 1000);
          reason = `Financial limit exceeded: ${amount} > 10000`;
          details = { field: "amount", value: amount, max: 10000 };
          break;
        case "prompt_injection":
          reason = randomChoice([
            "Prompt injection detected via LLM analysis",
            "Prompt injection: jailbreak pattern detected",
            "Prompt injection: instruction override attempt",
          ]);
          details = { detection_method: "llm", model: "claude-haiku-4-5-20251001" };
          break;
        case "tone_sentiment":
          const tone = randomChoice(["angry", "sarcastic", "threatening", "dismissive"]);
          reason = `Tone detected: ${tone}`;
          details = { tone, field: "body" };
          break;
        case "rate_limit":
          const key = randomChoice(AGENTS);
          reason = `Rate limit exceeded: 5 actions in 3600s for key '${key}'`;
          details = { key, count: 5, max_actions: 5, window_seconds: 3600 };
          break;
      }
    } else {
      status = "error";
      rule = randomChoice(RULES);
      reason = randomChoice([
        "API timeout after 10s",
        "LLM provider returned 503",
        "Connection refused to evaluation endpoint",
      ]);
      details = { original_error: reason };
    }

    events.push({
      eventId: randomUUID(),
      timestamp,
      status,
      rule,
      reason,
      details,
      elapsedMs: status === "approved" ? randomFloat(1, 15) : randomFloat(5, 200),
      payload: Math.random() < 0.3 ? { body: "Sample payload text...", amount: Math.round(Math.random() * 10000) } : null,
      metadata: { agent_id: randomChoice(AGENTS), session_id: `sess_${randomUUID().slice(0, 8)}` },
    });
  }

  return events;
}

async function main() {
  console.log("Seeding 2,000 mock events...");
  const events = generateEvents(2000);

  // Batch insert in chunks of 500
  for (let i = 0; i < events.length; i += 500) {
    const chunk = events.slice(i, i + 500);
    await prisma.auditEvent.createMany({ data: chunk });
    console.log(`  Inserted ${Math.min(i + 500, events.length)}/${events.length}`);
  }

  console.log("Done! Dashboard ready at http://localhost:3000");
}

main()
  .catch(console.error)
  .finally(() => prisma.$disconnect());
