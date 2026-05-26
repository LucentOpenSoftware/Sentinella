import { useState, useEffect } from "react";
import { Shield, Database, AlertTriangle, ExternalLink, RotateCcw, Loader2, Download } from "lucide-react";
import { Card } from "../components/Card";
import { getSignatureSources, setSignatureSource, rollbackSignatureSource, updateSignatureSource } from "../api/sentinella";
import { useDaemonContext } from "../hooks/DaemonContext";
import type { SignatureSourcesStatus, SignatureProviderInfo } from "../types/sentinella";

export function SignatureSourcesPage() {
  const { connected } = useDaemonContext();
  const [sources, setSources] = useState<SignatureSourcesStatus | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [restartNeeded, setRestartNeeded] = useState(false);
  const [updating, setUpdating] = useState(false);

  const handleUpdate = async () => {
    setUpdating(true);
    setError(null);
    setSuccess(null);
    try {
      const result = await updateSignatureSource();
      if (result.ok) {
        setSuccess(`Signatures downloaded (${result.files_activated || 0} files). Restart daemon to apply.`);
        setRestartNeeded(true);
      } else {
        setError(result.error || "Update failed");
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setUpdating(false);
    }
  };

  const refresh = () => {
    if (!connected) return;
    getSignatureSources().then(setSources).catch(() => {});
  };

  useEffect(() => {
    refresh();
  }, [connected]);

  const handleSelect = async (providerId: string | null) => {
    setPending(true);
    setError(null);
    setSuccess(null);
    try {
      if (providerId === null) {
        // Rollback to official-only.
        const result = await rollbackSignatureSource();
        if (result.ok) {
          setSuccess("Rolled back to official ClamAV only. Restart daemon to apply.");
          setRestartNeeded(true);
        } else {
          setError(result.error || "Rollback failed");
        }
      } else {
        const result = await setSignatureSource(providerId);
        if (result.ok) {
          setSuccess(`Provider "${providerId}" activated. Restart daemon to apply.`);
          setRestartNeeded(true);
        } else {
          setError(result.error || "Failed to set provider");
        }
      }
      refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setPending(false);
    }
  };

  if (!connected) {
    return (
      <div className="page-stack">
        <Card className="text-center py-14">
          <p className="text-[14px] text-[rgb(var(--t2))]">Connect to daemon to view signature sources.</p>
        </Card>
      </div>
    );
  }

  return (
    <div className="page-stack">
      {/* Header */}
      <Card>
        <div className="flex items-center gap-4 mb-1">
          <div className="w-10 h-10 rounded-xl bg-[rgb(var(--accent))]/8 flex items-center justify-center">
            <Database size={18} className="text-[rgb(var(--accent))]" />
          </div>
          <div>
            <h3 className="text-[18px] font-bold">Signature Sources</h3>
            <p className="text-[12px] text-[rgb(var(--t3))] mt-0.5">
              Manage detection intelligence providers
            </p>
          </div>
        </div>
      </Card>

      {/* Advanced feature notice */}
      <Card className="bg-[rgb(var(--amber))]/3 border border-[rgb(var(--amber))]/10">
        <div className="flex items-start gap-3">
          <AlertTriangle size={16} className="text-[rgb(var(--amber))] mt-0.5 flex-shrink-0" />
          <div>
            <p className="text-[12px] text-[rgb(var(--t1))] font-semibold">Advanced Feature</p>
            <p className="text-[11px] text-[rgb(var(--t2))] mt-1 leading-relaxed">
              Enhanced providers add detection coverage beyond official ClamAV signatures.
              Only one enhanced provider can be active at a time. Changing providers requires
              an engine rebuild and daemon restart.
            </p>
          </div>
        </div>
      </Card>

      {/* Status banners */}
      {error && (
        <Card className="bg-[rgb(var(--red))]/5 border border-[rgb(var(--red))]/15">
          <p className="text-[12px] text-[rgb(var(--red))]">{error}</p>
        </Card>
      )}
      {success && (
        <Card className="bg-[rgb(var(--green))]/5 border border-[rgb(var(--green))]/15">
          <p className="text-[12px] text-[rgb(var(--green))]">{success}</p>
        </Card>
      )}
      {restartNeeded && (
        <Card className="bg-[rgb(var(--accent))]/5 border border-[rgb(var(--accent))]/15">
          <div className="flex items-center gap-2">
            <RotateCcw size={14} className="text-[rgb(var(--accent))]" />
            <p className="text-[12px] text-[rgb(var(--accent))] font-semibold">
              Daemon restart required to apply provider change.
            </p>
          </div>
        </Card>
      )}

      {/* Download signatures for active provider */}
      {sources?.enhanced?.active_provider && (
        <Card>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-[13px] font-semibold">Download Enhanced Signatures</p>
              <p className="text-[11px] text-[rgb(var(--t3))]">
                Fetch latest signatures from {sources.enhanced.active_name || sources.enhanced.active_provider}
              </p>
            </div>
            <button
              onClick={handleUpdate}
              disabled={updating || pending}
              className="flex items-center gap-2 px-3 py-1.5 text-[12px] font-semibold rounded-lg bg-[rgb(var(--accent))]/10 text-[rgb(var(--accent))] hover:bg-[rgb(var(--accent))]/20 disabled:opacity-40 transition-colors"
            >
              {updating ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
              {updating ? "Downloading..." : "Download Now"}
            </button>
          </div>
        </Card>
      )}

      {/* Official ClamAV — always enabled */}
      <Card>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[rgb(var(--green))]/10 flex items-center justify-center">
              <Shield size={16} className="text-[rgb(var(--green))]" />
            </div>
            <div>
              <h4 className="text-[14px] font-semibold">Official ClamAV</h4>
              <p className="text-[11px] text-[rgb(var(--t3))]">
                {sources?.core?.name || "Core signature database"} — always enabled
              </p>
            </div>
          </div>
          <span className="text-[10px] font-bold text-[rgb(var(--green))] bg-[rgb(var(--green))]/8 px-2 py-1 rounded-full uppercase">
            Required
          </span>
        </div>
      </Card>

      {/* Enhanced providers */}
      <div>
        <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[rgb(var(--t3))]/40 mb-3 px-1">
          Enhanced Providers (select one)
        </p>
        <div className="space-y-3">
          {/* "None" option */}
          <ProviderCard
            provider={null}
            isActive={!sources?.enhanced?.active_provider}
            disabled={pending}
            onSelect={() => handleSelect(null)}
          />

          {/* Provider cards */}
          {sources?.available_providers?.map((p) => (
            <ProviderCard
              key={p.id}
              provider={p}
              isActive={p.active}
              disabled={pending}
              onSelect={() => handleSelect(p.id)}
            />
          ))}
        </div>
      </div>

      {/* Loading overlay */}
      {pending && (
        <Card className="text-center py-6">
          <Loader2 size={20} className="animate-spin mx-auto text-[rgb(var(--accent))] mb-2" />
          <p className="text-[12px] text-[rgb(var(--t2))]">Applying provider change...</p>
        </Card>
      )}

      {/* Footer */}
      <p className="text-center text-[10px] text-[rgb(var(--t3))]/20">
        Enhanced providers are optional · one provider at a time · changes require restart
      </p>
    </div>
  );
}

function ProviderCard({
  provider,
  isActive,
  disabled,
  onSelect,
}: {
  provider: SignatureProviderInfo | null;
  isActive: boolean;
  disabled: boolean;
  onSelect: () => void;
}) {
  if (!provider) {
    // "None" option
    return (
      <div onClick={disabled ? undefined : onSelect} className={disabled ? "opacity-50" : "cursor-pointer"}>
      <Card
        className={`transition-all ${
          isActive
            ? "ring-2 ring-[rgb(var(--accent))]/40 bg-[rgb(var(--accent))]/3"
            : "hover:bg-[rgb(var(--raised))]/20"
        }`}
      >
        <div className="flex items-center gap-3">
          <div className={`w-4 h-4 rounded-full border-2 flex items-center justify-center ${
            isActive ? "border-[rgb(var(--accent))] bg-[rgb(var(--accent))]" : "border-[rgb(var(--t3))]/30"
          }`}>
            {isActive && <div className="w-1.5 h-1.5 rounded-full bg-white" />}
          </div>
          <div>
            <p className="text-[13px] font-semibold">Official ClamAV Only</p>
            <p className="text-[11px] text-[rgb(var(--t3))]">No enhanced signatures — lowest footprint, zero FP risk from third parties</p>
          </div>
        </div>
      </Card>
      </div>
    );
  }

  const riskColor = provider.fp_risk === "Low" ? "green" : provider.fp_risk === "Moderate" ? "amber" : "red";
  const stabColor = provider.stability === "Established" ? "green" : provider.stability === "Community" ? "accent" : "amber";

  return (
    <div onClick={disabled ? undefined : onSelect} className={disabled ? "opacity-50" : "cursor-pointer"}>
    <Card
      className={`transition-all ${
        isActive
          ? "ring-2 ring-[rgb(var(--accent))]/40 bg-[rgb(var(--accent))]/3"
          : "hover:bg-[rgb(var(--raised))]/20"
      }`}
    >
      <div className="flex items-start gap-3">
        {/* Radio indicator */}
        <div className={`w-4 h-4 rounded-full border-2 flex items-center justify-center mt-0.5 flex-shrink-0 ${
          isActive ? "border-[rgb(var(--accent))] bg-[rgb(var(--accent))]" : "border-[rgb(var(--t3))]/30"
        }`}>
          {isActive && <div className="w-1.5 h-1.5 rounded-full bg-white" />}
        </div>

        <div className="flex-1 min-w-0">
          {/* Header */}
          <div className="flex items-center gap-2 mb-1">
            <h4 className="text-[13px] font-semibold">{provider.name}</h4>
            <span className={`text-[8px] font-bold px-1.5 py-0.5 rounded-full uppercase tracking-wider text-[rgb(var(--${stabColor}))] bg-[rgb(var(--${stabColor}))]/8`}>
              {provider.stability}
            </span>
            {provider.recommendation === "Recommended" && (
              <span className="text-[8px] font-bold px-1.5 py-0.5 rounded-full uppercase tracking-wider text-[rgb(var(--green))] bg-[rgb(var(--green))]/8">
                Recommended
              </span>
            )}
          </div>

          <p className="text-[11px] text-[rgb(var(--t2))] leading-relaxed mb-2">{provider.description}</p>

          {/* Stats grid */}
          <div className="grid grid-cols-4 gap-3 mb-2">
            <div>
              <p className="text-[14px] font-bold text-[rgb(var(--t1))]">{(provider.estimated_signatures / 1000).toFixed(0)}K</p>
              <p className="text-[9px] text-[rgb(var(--t3))]">Signatures</p>
            </div>
            <div>
              <p className="text-[14px] font-bold text-[rgb(var(--t1))]">+{provider.estimated_footprint_mb}</p>
              <p className="text-[9px] text-[rgb(var(--t3))]">MB mapped</p>
            </div>
            <div>
              <p className={`text-[14px] font-bold text-[rgb(var(--${riskColor}))]`}>{provider.fp_risk}</p>
              <p className="text-[9px] text-[rgb(var(--t3))]">FP risk</p>
            </div>
            <div>
              <p className="text-[14px] font-bold text-[rgb(var(--t2))]">{provider.update_frequency.split(' ')[0]}</p>
              <p className="text-[9px] text-[rgb(var(--t3))]">Updates</p>
            </div>
          </div>

          {/* FP explanation */}
          <p className="text-[10px] text-[rgb(var(--t3))]/60 leading-relaxed mb-2">{provider.fp_explanation}</p>

          {/* Footer: focus + license */}
          <div className="flex items-center gap-3 text-[9px] text-[rgb(var(--t3))]/40">
            <span>Focus: {provider.focus}</span>
            <span>·</span>
            <span>{provider.license}</span>
            {provider.homepage && (
              <>
                <span>·</span>
                <a href={provider.homepage} target="_blank" rel="noopener" className="flex items-center gap-0.5 text-[rgb(var(--accent))]/60 hover:text-[rgb(var(--accent))]">
                  Website <ExternalLink size={8} />
                </a>
              </>
            )}
          </div>
        </div>
      </div>
    </Card>
    </div>
  );
}
