import React from 'react';
import { Award, ShieldAlert, FileText, CheckCircle, Clock, AlertOctagon } from 'lucide-react';

interface RiskCardsTabProps {
  riskCards: any[];
}

export default function RiskCardsTab({ riskCards }: RiskCardsTabProps) {
  const getScoreColor = (score: number) => {
    if (score >= 80) return 'var(--accent-red)';
    if (score >= 50) return 'var(--accent-amber)';
    return 'var(--accent-emerald)';
  };

  return (
    <div className="fade-in">
      <div style={{ marginBottom: '1.5rem' }}>
        <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <FileText size={20} color="var(--accent-cyan)" />
          Explainable AI Risk Cards
        </h3>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', marginTop: '0.25rem' }}>
          Human-readable cybersecurity postures generated automatically for every security event, alert, and automated action. Designed for Security Engineers, CISOs, Compliance Officers, and Auditors.
        </p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        {riskCards.length === 0 ? (
          <p style={{ color: 'var(--text-tertiary)', fontStyle: 'italic', textAlign: 'center', padding: '3rem', background: 'rgba(255,255,255,0.01)', borderRadius: 'var(--r-md)' }}>
            No explainable AI risk cards have been generated yet. Try running a Blast Radius Simulation or triggering an Autonomous Revocation to generate a card.
          </p>
        ) : (
          riskCards.map((card) => {
            const scoreColor = getScoreColor(card.riskScore);
            const timeline = card.timeline || [];
            const assets = card.assetsAffected || [];

            return (
              <div
                key={card.id}
                className="card"
                style={{
                  padding: '2rem',
                  background: 'var(--glass)',
                  border: `1.5px solid rgba(255, 255, 255, 0.08)`,
                  position: 'relative',
                  overflow: 'hidden',
                }}
              >
                {/* Visual Gradient Border Accent */}
                <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: '4px', background: `linear-gradient(90deg, ${scoreColor}, var(--accent))` }} />

                {/* Header */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '1.5rem' }}>
                  <div>
                    <span className="badge badge-purple" style={{ fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      {card.targetType} Posture Card
                    </span>
                    <h2 style={{ marginTop: '0.4rem', fontSize: '1.25rem', fontWeight: 800 }}>{card.triggerEvent}</h2>
                    <span style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)', display: 'block', marginTop: '0.25rem' }}>
                      Card ID: {card.id} • Created {new Date(card.createdAt).toLocaleString()}
                    </span>
                  </div>

                  <div style={{ display: 'flex', gap: '1rem' }}>
                    <div style={{ textAlign: 'center' }}>
                      <span style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', textTransform: 'uppercase', display: 'block' }}>Risk Score</span>
                      <strong style={{ fontSize: '1.5rem', fontWeight: 800, color: scoreColor }}>
                        {card.riskScore}%
                      </strong>
                    </div>
                    <div style={{ textAlign: 'center' }}>
                      <span style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', textTransform: 'uppercase', display: 'block' }}>AI Confidence</span>
                      <strong style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--accent-cyan)' }}>
                        {Math.round(card.confidenceScore * 100)}%
                      </strong>
                    </div>
                  </div>
                </div>

                {/* Grid details */}
                <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '2rem', borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '1.5rem' }}>
                  {/* Left Column */}
                  <div>
                    <div style={{ marginBottom: '1.2rem' }}>
                      <strong style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-primary)', marginBottom: '0.4rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        Business Impact
                      </strong>
                      <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
                        {card.businessImpact}
                      </p>
                    </div>

                    <div style={{ marginBottom: '1.2rem' }}>
                      <strong style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-primary)', marginBottom: '0.4rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        Compliance / Regulatory Impact
                      </strong>
                      <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
                        {card.complianceImpact}
                      </p>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginTop: '1.5rem' }}>
                      <div style={{ background: 'rgba(255,255,255,0.02)', padding: '0.8rem', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.04)' }}>
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', display: 'block', marginBottom: '0.25rem' }}>Recommended Remediation</span>
                        <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>{card.recommendedAction}</span>
                      </div>
                      <div style={{ background: 'rgba(255,255,255,0.02)', padding: '0.8rem', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.04)' }}>
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', display: 'block', marginBottom: '0.25rem' }}>Executed Action</span>
                        <span style={{ fontSize: '0.82rem', color: 'var(--accent-emerald)', fontWeight: 600 }}>{card.executedAction}</span>
                      </div>
                    </div>
                  </div>

                  {/* Right Column */}
                  <div style={{ borderLeft: '1px solid rgba(255,255,255,0.06)', paddingLeft: '2rem' }}>
                    {/* Affected Assets */}
                    <div style={{ marginBottom: '1.2rem' }}>
                      <strong style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-primary)', marginBottom: '0.4rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        Assets in Compromise Path
                      </strong>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                        {assets.map((asset: any, idx: number) => (
                          <span key={idx} className="badge badge-purple" style={{ fontSize: '0.7rem' }}>
                            {asset.name} ({asset.type})
                          </span>
                        ))}
                      </div>
                    </div>

                    {/* Timeline */}
                    <div style={{ marginBottom: '1.2rem' }}>
                      <strong style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-primary)', marginBottom: '0.4rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        Detection Timeline
                      </strong>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                        {timeline.map((step: any, idx: number) => (
                          <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem' }}>
                            <span style={{ color: 'var(--text-secondary)' }}>• {step.step}</span>
                            <span style={{ color: 'var(--text-tertiary)' }}>{new Date(step.time).toLocaleTimeString()}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '1rem', marginTop: '1rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                      <div>
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', display: 'block' }}>Validation Checks</span>
                        <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{card.validationPerformed}</span>
                      </div>
                      <div>
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', display: 'block' }}>Rollback Plan</span>
                        <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{card.rollbackPlan}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
