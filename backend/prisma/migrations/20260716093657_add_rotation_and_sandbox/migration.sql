-- AlterTable
ALTER TABLE "secrets" ADD COLUMN     "is_rotatable" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "last_rotation_time" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN     "risk_level" TEXT NOT NULL DEFAULT 'LOW',
ADD COLUMN     "risk_score" DOUBLE PRECISION NOT NULL DEFAULT 0,
ADD COLUMN     "rotation_frequency_days" INTEGER NOT NULL DEFAULT 90;

-- CreateTable
CREATE TABLE "rotation_logs" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "secret_id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "trigger_type" TEXT NOT NULL,
    "old_version" INTEGER NOT NULL,
    "new_version" INTEGER NOT NULL,
    "status" TEXT NOT NULL,
    "risk_score_before" DOUBLE PRECISION NOT NULL,
    "rotation_reason" TEXT NOT NULL,
    "risk_factors" JSONB NOT NULL DEFAULT '{}',
    "ai_confidence" DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    "timeline" JSONB NOT NULL DEFAULT '[]',
    "error_log" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "rotation_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_sessions" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "tenant_id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "created_by" UUID NOT NULL,
    "status" TEXT NOT NULL,
    "resources" JSONB NOT NULL DEFAULT '[]',
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "destroyed_at" TIMESTAMPTZ(6),
    "destruction_certificate" TEXT,

    CONSTRAINT "sandbox_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "rotation_logs_tenant_id_idx" ON "rotation_logs"("tenant_id");

-- CreateIndex
CREATE INDEX "sandbox_sessions_tenant_id_idx" ON "sandbox_sessions"("tenant_id");

-- AddForeignKey
ALTER TABLE "rotation_logs" ADD CONSTRAINT "rotation_logs_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sandbox_sessions" ADD CONSTRAINT "sandbox_sessions_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
