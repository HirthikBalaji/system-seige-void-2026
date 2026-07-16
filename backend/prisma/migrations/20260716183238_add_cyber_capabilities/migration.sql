-- AlterTable
ALTER TABLE "secrets" ADD COLUMN     "expires_at" TIMESTAMPTZ(6),
ADD COLUMN     "time_lock_metadata" JSONB;

-- CreateTable
CREATE TABLE "workload_identities" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "tenant_id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "attestationType" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "selector" JSONB NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "workload_identities_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "workload_certificates" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "workload_id" UUID NOT NULL,
    "serial_number" TEXT NOT NULL,
    "common_name" TEXT NOT NULL,
    "sans" JSONB NOT NULL DEFAULT '[]',
    "certificate_pem" TEXT NOT NULL,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "status" TEXT NOT NULL,
    "revoked_at" TIMESTAMPTZ(6),
    "revocation_reason" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "workload_certificates_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "autonomous_revocations" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "tenant_id" UUID NOT NULL,
    "finding_id" UUID,
    "provider" TEXT NOT NULL,
    "credential_identifier" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "executedActions" JSONB NOT NULL DEFAULT '[]',
    "rollback_plan" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "autonomous_revocations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "digital_twin_nodes" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "tenant_id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "properties" JSONB NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "digital_twin_nodes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "digital_twin_edges" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "tenant_id" UUID NOT NULL,
    "source_node_id" UUID NOT NULL,
    "target_node_id" UUID NOT NULL,
    "type" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "digital_twin_edges_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "blast_radius_simulations" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "tenant_id" UUID NOT NULL,
    "secret_id" UUID,
    "start_node_id" UUID NOT NULL,
    "risk_score" DOUBLE PRECISION NOT NULL,
    "compromisedNodes" JSONB NOT NULL DEFAULT '[]',
    "lateralPaths" JSONB NOT NULL DEFAULT '[]',
    "business_impact" TEXT NOT NULL,
    "recommendations" JSONB NOT NULL DEFAULT '[]',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "blast_radius_simulations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "federated_intelligence_models" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "tenant_id" UUID NOT NULL,
    "pattern_type" TEXT NOT NULL,
    "extracted_pattern" JSONB NOT NULL,
    "is_shared" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "federated_intelligence_models_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "global_intelligence_rules" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "rule_name" TEXT NOT NULL,
    "pattern" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "source_count" INTEGER NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "global_intelligence_rules_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "risk_cards" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "tenant_id" UUID NOT NULL,
    "target_type" TEXT NOT NULL,
    "target_id" TEXT NOT NULL,
    "risk_score" DOUBLE PRECISION NOT NULL,
    "confidence_score" DOUBLE PRECISION NOT NULL,
    "trigger_event" TEXT NOT NULL,
    "evidence" JSONB NOT NULL DEFAULT '{}',
    "timeline" JSONB NOT NULL DEFAULT '[]',
    "assetsAffected" JSONB NOT NULL DEFAULT '[]',
    "business_impact" TEXT NOT NULL,
    "compliance_impact" TEXT NOT NULL,
    "recommended_action" TEXT NOT NULL,
    "executed_action" TEXT NOT NULL,
    "validation_performed" TEXT NOT NULL,
    "rollback_plan" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "risk_cards_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "workload_identities_tenant_id_idx" ON "workload_identities"("tenant_id");

-- CreateIndex
CREATE INDEX "workload_certificates_workload_id_idx" ON "workload_certificates"("workload_id");

-- CreateIndex
CREATE INDEX "autonomous_revocations_tenant_id_idx" ON "autonomous_revocations"("tenant_id");

-- CreateIndex
CREATE INDEX "digital_twin_nodes_tenant_id_idx" ON "digital_twin_nodes"("tenant_id");

-- CreateIndex
CREATE INDEX "digital_twin_edges_tenant_id_idx" ON "digital_twin_edges"("tenant_id");

-- CreateIndex
CREATE INDEX "blast_radius_simulations_tenant_id_idx" ON "blast_radius_simulations"("tenant_id");

-- CreateIndex
CREATE INDEX "federated_intelligence_models_tenant_id_idx" ON "federated_intelligence_models"("tenant_id");

-- CreateIndex
CREATE INDEX "risk_cards_tenant_id_idx" ON "risk_cards"("tenant_id");

-- AddForeignKey
ALTER TABLE "workload_identities" ADD CONSTRAINT "workload_identities_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "workload_certificates" ADD CONSTRAINT "workload_certificates_workload_id_fkey" FOREIGN KEY ("workload_id") REFERENCES "workload_identities"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "autonomous_revocations" ADD CONSTRAINT "autonomous_revocations_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "digital_twin_nodes" ADD CONSTRAINT "digital_twin_nodes_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "digital_twin_edges" ADD CONSTRAINT "digital_twin_edges_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "blast_radius_simulations" ADD CONSTRAINT "blast_radius_simulations_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "federated_intelligence_models" ADD CONSTRAINT "federated_intelligence_models_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_cards" ADD CONSTRAINT "risk_cards_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
