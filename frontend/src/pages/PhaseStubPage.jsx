import { EmptyState, StatusBadge } from '../components/UiPrimitives';

export default function PhaseStubPage({ title, subtitle, phaseNote }) {
  return (
    <div>
      <header className="soc-page-header">
        <div>
          <h1 className="soc-page-title">{title}</h1>
          <p className="soc-page-subtitle">{subtitle}</p>
        </div>
        <StatusBadge status="idle" label={phaseNote} />
      </header>

      <EmptyState
        title={`${title} view scheduled next`}
        description={`Phase 7 established authentication, protected routing, and live collector status headers. ${title} data visualizations and actions will be wired to Supabase in ${phaseNote}.`}
      />
    </div>
  );
}
