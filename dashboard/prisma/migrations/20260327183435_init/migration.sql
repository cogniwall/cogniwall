-- CreateTable
CREATE TABLE "audit_events" (
    "id" UUID NOT NULL,
    "event_id" UUID NOT NULL,
    "timestamp" TIMESTAMPTZ NOT NULL,
    "status" TEXT NOT NULL,
    "rule" TEXT,
    "reason" TEXT,
    "details" JSONB,
    "elapsed_ms" DOUBLE PRECISION NOT NULL,
    "payload" JSONB,
    "metadata" JSONB,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "audit_events_event_id_key" ON "audit_events"("event_id");

-- CreateIndex
CREATE INDEX "audit_events_timestamp_idx" ON "audit_events"("timestamp" DESC);

-- CreateIndex
CREATE INDEX "audit_events_status_idx" ON "audit_events"("status");

-- CreateIndex
CREATE INDEX "audit_events_rule_idx" ON "audit_events"("rule");
