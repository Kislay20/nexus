"use client";
import { useEffect, useState, useCallback } from "react";
import { approveWithPasskey, enrollPasskey } from "../lib/webauthn";

interface TraceData {
  seq: number;
  kind: string;
  reservation_id: string | null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  body: Record<string, any>;
}

interface ToastMessage {
  type: "success" | "error" | "info";
  title: string;
  detail: string;
}

interface DeepLinkAction {
  id: string;
  type: "approve" | "reject";
}

export default function Dashboard() {
  const [traces, setTraces] = useState<TraceData[]>([]);
  const [ledgerStatus, setLedgerStatus] = useState<{
    intact: boolean | null;
    text: string;
  }>({ intact: null, text: "Unverified" });
  const [isAuthenticating, setIsAuthenticating] = useState<string | null>(null);
  const [isEnrolling, setIsEnrolling] = useState(false);
  const [isSimulating, setIsSimulating] = useState(false);
  const [toast, setToast] = useState<ToastMessage | null>(null);
  const [deepAction, setDeepAction] = useState<DeepLinkAction | null>(null);

  const showToast = useCallback(
    (type: ToastMessage["type"], title: string, detail: string) => {
      setToast({ type, title, detail });
      setTimeout(() => setToast(null), 4500);
    },
    []
  );

  const fetchTraces = useCallback(async () => {
    try {
      const res = await fetch("/api/gateway/traces", { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        setTraces(data.reverse());
      }
    } catch (err) {
      console.error("Failed to fetch traces:", err);
    }
  }, []);

  const handleSimulateAgent = async () => {
    setIsSimulating(true);
    try {
      const res = await fetch("/api/gateway/demo/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      if (res.ok) {
        const data = await res.json();
        showToast(
          "info",
          "Agent Proposal Triggered ($90.00)",
          `Order ${data.reservation_id?.replace("rsv_", "").slice(0, 8)}... escalated for biometric approval.`
        );
        await fetchTraces();
      } else {
        showToast("error", "Simulation Failed", await res.text());
      }
    } catch (err: unknown) {
      showToast("error", "Simulation Error", (err as Error).message);
    } finally {
      setIsSimulating(false);
    }
  };

  const handlePasskeyApprove = useCallback(
    async (id: string) => {
      setIsAuthenticating(id);
      try {
        const res = await approveWithPasskey(id);
        if (res.status === "APPROVED" || res.status === "CAPTURED") {
          setDeepAction(null);
          showToast(
            "success",
            "Biometric Signature Verified",
            `Order ${id.replace("rsv_", "").slice(0, 8)}... captured via PayPal Sandbox.`
          );
        }
        await fetchTraces();
      } catch (err: unknown) {
        showToast("error", "Biometric Auth Cancelled", (err as Error).message);
      } finally {
        setIsAuthenticating(null);
      }
    },
    [fetchTraces, showToast]
  );

  const handleReject = useCallback(
    async (id: string) => {
      setIsAuthenticating(id);
      try {
        const res = await fetch(`/api/gateway/reservations/${id}/reject`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Approver-Key": "change-me",
          },
        });
        if (!res.ok) {
          showToast("error", "Reject Failed", await res.text());
        } else {
          setDeepAction(null);
          showToast(
            "info",
            "Order Rejected",
            `Reservation ${id.replace("rsv_", "").slice(0, 8)}... was voided.`
          );
        }
        await fetchTraces();
      } catch (err: unknown) {
        showToast("error", "Network Error", (err as Error).message);
      } finally {
        setIsAuthenticating(null);
      }
    },
    [fetchTraces, showToast]
  );

  // 1. Live Smart Polling
  useEffect(() => {
    const timer = setTimeout(() => {
      fetchTraces();
    }, 0);
    const interval = setInterval(fetchTraces, 1500);
    return () => {
      clearTimeout(timer);
      clearInterval(interval);
    };
  }, [fetchTraces]);

  // 2. Telegram Deep Link Handler (Strict-Mode & iOS Safari Safe)
  useEffect(() => {
    const timer = setTimeout(() => {
      if (typeof window !== "undefined") {
        const urlParams = new URLSearchParams(window.location.search);
        const action = urlParams.get("action");
        const resId = urlParams.get("id");

        if ((action === "approve" || action === "reject") && resId) {
          setDeepAction({ id: resId, type: action });
          window.history.replaceState({}, document.title, window.location.pathname);
        }
      }
    }, 50);

    return () => clearTimeout(timer);
  }, []);

  const verifyLedger = async () => {
    setLedgerStatus({ intact: null, text: "Verifying hash-chain..." });
    try {
      const res = await fetch("/api/gateway/audit/verify", { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        if (data.intact) {
          setLedgerStatus({ intact: true, text: "Chain Intact (Ed25519 Verified)" });
          showToast(
            "success",
            "Hash-Chain Verified",
            "Zero tampering detected across all ledger blocks."
          );
        } else {
          setLedgerStatus({
            intact: false,
            text: `TAMPERED at seq #${data.first_bad_seq}`,
          });
          showToast(
            "error",
            "Tampering Detected!",
            `Cryptographic break at sequence ${data.first_bad_seq}.`
          );
        }
      } else {
        setLedgerStatus({ intact: false, text: "Auditor Unreachable" });
      }
    } catch (err) {
      setLedgerStatus({ intact: false, text: "Network Error" });
      console.error(err);
    }
  };

  const handleExportAudit = async () => {
    try {
      const res = await fetch("/api/gateway/audit/export", { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "nexus_audit_proof.json";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast(
          "success",
          "Audit Bundle Exported",
          "Downloaded nexus_audit_proof.json for offline verification."
        );
      } else {
        showToast("error", "Export Failed", "Could not generate audit proof bundle.");
      }
    } catch (err: unknown) {
      showToast("error", "Export Error", (err as Error).message);
    }
  };

  const handleEnrollDevice = async () => {
    setIsEnrolling(true);
    try {
      await enrollPasskey("Admin Device (WebAuthn)");
      showToast(
        "success",
        "Passkey Enrolled",
        "This device is now cryptographically bound for biometric approvals."
      );
    } catch (err: unknown) {
      showToast("error", "Enrollment Failed", (err as Error).message);
    } finally {
      setIsEnrolling(false);
    }
  };

  const getStatusBadge = (decision: string, code: string) => {
    if (decision === "ALLOW" || code === "OK" || code === "CAPTURED")
      return (
        <span className="inline-flex items-center gap-1.5 bg-emerald-500/10 text-emerald-700 px-3 py-1 rounded-full text-xs font-bold border border-emerald-500/20">
          <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
          SUCCESS: CAPTURED
        </span>
      );

    if (decision === "DENY" || code === "VOIDED" || code === "REJECTED")
      return (
        <span className="inline-flex items-center gap-1.5 bg-rose-500/10 text-rose-700 px-3 py-1 rounded-full text-xs font-bold border border-rose-500/20">
          <span className="w-2 h-2 rounded-full bg-rose-500"></span>
          BLOCKED: {code}
        </span>
      );

    if (decision === "ESCALATE")
      return (
        <span className="inline-flex items-center gap-1.5 bg-amber-500/15 text-amber-800 px-3 py-1 rounded-full text-xs font-bold border border-amber-500/30">
          <span className="w-2 h-2 rounded-full bg-amber-500 animate-ping"></span>
          AWAITING BIOMETRICS
        </span>
      );

    return (
      <span className="inline-flex items-center bg-slate-100 text-slate-700 px-2.5 py-1 rounded-md text-xs font-bold">
        {code}
      </span>
    );
  };

  const decisions = traces.filter((t) => t.kind === "DECISION");
  const lifecycles = traces.filter((t) => t.kind === "LIFECYCLE");

  const rows = decisions.map((trace) => {
    const b = trace.body;
    const resId = trace.reservation_id || b.reservation_id || "N/A";
    const relatedEvents = lifecycles.filter((l) => l.body?.reservation_id === resId);
    const latestEvent = relatedEvents.length > 0 ? relatedEvents[0].body.event : null;

    let displayStatus = b.decision;
    let displayCode = b.final_code;
    let showActions = b.decision === "ESCALATE" && b.final_code === "ESCALATE_OVER_THRESHOLD";

    if (latestEvent) {
      if (latestEvent === "CAPTURED" || latestEvent === "APPROVED") {
        displayStatus = "ALLOW";
        displayCode = "CAPTURED";
        showActions = false;
      } else if (latestEvent === "VOIDED" || latestEvent === "REJECTED") {
        displayStatus = "DENY";
        displayCode = latestEvent;
        showActions = false;
      }
    }

    return {
      seq: trace.seq,
      resId,
      shortId: resId.replace("rsv_", ""),
      offerId: b.agent_claim?.offer_id || "Unknown",
      total: b.resolved?.total || null,
      currency: b.resolved?.offer?.currency || "USD",
      displayStatus,
      displayCode,
      showActions,
    };
  });

  const pendingCount = rows.filter((r) => r.showActions).length;
  const capturedCount = rows.filter((r) => r.displayStatus === "ALLOW").length;
  const blockedCount = rows.filter((r) => r.displayStatus === "DENY").length;

  return (
    <main className="min-h-screen bg-[#F8FAFC] text-slate-900 font-sans pb-12">
      {/* FLOATING TOAST NOTIFICATION */}
      {toast && (
        <div className="fixed bottom-5 right-5 left-5 sm:left-auto sm:w-96 z-50 animate-in fade-in slide-in-from-bottom-4">
          <div
            className={`p-4 rounded-2xl shadow-xl border backdrop-blur-md flex items-start justify-between gap-3 ${
              toast.type === "success"
                ? "bg-emerald-950/95 text-white border-emerald-700"
                : toast.type === "error"
                ? "bg-rose-950/95 text-white border-rose-700"
                : "bg-slate-900/95 text-white border-slate-700"
            }`}
          >
            <div>
              <p className="text-xs font-extrabold uppercase tracking-wider opacity-80">
                {toast.type === "success"
                  ? "🛡️ Verified"
                  : toast.type === "error"
                  ? "⚠️ Alert"
                  : "ℹ️ Update"}
              </p>
              <h4 className="font-bold text-sm mt-0.5">{toast.title}</h4>
              <p className="text-xs opacity-90 mt-1 leading-relaxed">{toast.detail}</p>
            </div>
            <button
              onClick={() => setToast(null)}
              className="text-xs opacity-70 hover:opacity-100 p-1"
            >
              ✕
            </button>
          </div>
        </div>
      )}

      {/* TELEGRAM DEEP-LINK ACTION MODAL (iOS Safari Safe & POST Behind Click) */}
      {deepAction && (
        <div className="fixed inset-0 bg-slate-950/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-3xl p-6 max-w-sm w-full shadow-2xl border border-indigo-100 text-center">
            <div
              className={`w-14 h-14 rounded-2xl flex items-center justify-center text-2xl mx-auto mb-3 shadow-inner ${
                deepAction.type === "approve"
                  ? "bg-indigo-50 text-indigo-600"
                  : "bg-rose-50 text-rose-600"
              }`}
            >
              {deepAction.type === "approve" ? "🛡️" : "⚠️"}
            </div>
            <h3 className="text-lg font-extrabold text-slate-900">
              {deepAction.type === "approve"
                ? "Biometric Escalation"
                : "Confirm Rejection"}
            </h3>
            <p className="text-xs text-slate-500 mt-1 font-mono">
              Order: {deepAction.id.replace("rsv_", "").slice(0, 14)}...
            </p>
            <p className="text-xs text-slate-600 mt-3 leading-relaxed">
              {deepAction.type === "approve"
                ? "Tap below to cryptographically sign this transaction with your hardware Passkey (Fingerprint / FaceID / PIN)."
                : "Tap below to void the PayPal authorization hold and reject this order."}
            </p>
            <div className="flex flex-col gap-2 mt-5">
              <button
                onClick={() =>
                  deepAction.type === "approve"
                    ? handlePasskeyApprove(deepAction.id)
                    : handleReject(deepAction.id)
                }
                disabled={isAuthenticating === deepAction.id}
                className={`w-full py-3.5 px-4 text-white font-bold text-sm rounded-xl shadow-lg transition-all cursor-pointer disabled:opacity-50 ${
                  deepAction.type === "approve"
                    ? "bg-indigo-600 hover:bg-indigo-700 shadow-indigo-200"
                    : "bg-rose-600 hover:bg-rose-700 shadow-rose-200"
                }`}
              >
                {isAuthenticating === deepAction.id
                  ? deepAction.type === "approve"
                    ? "⏳ Verifying Biometrics..."
                    : "⏳ Voiding Order..."
                  : deepAction.type === "approve"
                  ? "🔓 Approve with Passkey"
                  : "❌ Confirm Reject & Void"}
              </button>
              <button
                onClick={() => setDeepAction(null)}
                className="w-full py-2.5 text-xs font-bold text-slate-400 hover:text-slate-600 cursor-pointer"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="max-w-6xl mx-auto px-4 sm:px-6 pt-5 sm:pt-8">
        {/* RESPONSIVE FINTECH HEADER */}
        <header className="bg-white p-5 sm:p-6 rounded-2xl shadow-sm border border-slate-200/80 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="flex items-start sm:items-center gap-3.5">
            <div className="bg-indigo-600 text-white w-11 h-11 rounded-xl flex items-center justify-center text-xl font-bold shadow-md shadow-indigo-200 shrink-0">
              ⬡
            </div>
            <div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <h1 className="text-xl sm:text-2xl font-extrabold tracking-tight text-slate-900">
                  Nexus Operations
                </h1>
                <span className="inline-flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider bg-emerald-50 text-emerald-700 px-2.5 py-0.5 rounded-full border border-emerald-200">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                  Live Sync
                </span>
              </div>
              <p className="text-slate-500 text-xs sm:text-sm font-medium mt-0.5">
                ZERO-TRUST AGENTIC COMMERCE LEDGER
              </p>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5 w-full lg:w-auto">
            {ledgerStatus.intact !== null && (
              <span
                className={`text-xs font-bold px-3 py-2 rounded-xl text-center border ${
                  ledgerStatus.intact
                    ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                    : "bg-rose-50 text-rose-700 border-rose-200"
                }`}
              >
                {ledgerStatus.intact ? "✅ " : "🚨 "}
                {ledgerStatus.text}
              </span>
            )}
            <div className="grid grid-cols-2 sm:flex flex-wrap gap-2">
              <button
                onClick={handleSimulateAgent}
                disabled={isSimulating}
                className="text-xs font-bold bg-amber-500 text-white px-3.5 py-2.5 rounded-xl hover:bg-amber-600 active:scale-[0.99] transition-all cursor-pointer flex items-center justify-center gap-1.5 shadow-xs disabled:opacity-50"
              >
                <span>🤖</span>
                <span>{isSimulating ? "Simulating..." : "Simulate Agent ($90)"}</span>
              </button>
              <button
                onClick={handleEnrollDevice}
                disabled={isEnrolling}
                className="text-xs font-bold bg-indigo-50 text-indigo-700 border border-indigo-200/80 px-3.5 py-2.5 rounded-xl hover:bg-indigo-100 active:scale-[0.99] transition-all cursor-pointer flex items-center justify-center gap-1.5"
              >
                <span>🔒</span>
                <span>{isEnrolling ? "Enrolling..." : "Enroll Passkey"}</span>
              </button>
              <button
                onClick={verifyLedger}
                className="text-xs font-bold bg-slate-900 text-white px-3.5 py-2.5 rounded-xl hover:bg-slate-800 active:scale-[0.99] transition-all cursor-pointer flex items-center justify-center gap-1.5"
              >
                <span>⛓️</span>
                <span>Verify Chain</span>
              </button>
              <button
                onClick={handleExportAudit}
                className="text-xs font-bold bg-slate-100 text-slate-700 border border-slate-300 px-3.5 py-2.5 rounded-xl hover:bg-slate-200 active:scale-[0.99] transition-all cursor-pointer flex items-center justify-center gap-1.5"
              >
                <span>📦</span>
                <span>Export Proof</span>
              </button>
            </div>
          </div>
        </header>

        {/* KPI METRICS BAR */}
        <section className="grid grid-cols-3 gap-3 sm:gap-4 my-5">
          <div className="bg-white p-3.5 sm:p-4 rounded-2xl border border-slate-200/70 shadow-xs">
            <p className="text-[10px] sm:text-xs font-bold uppercase tracking-wider text-amber-600">
              Awaiting Biometrics
            </p>
            <p className="text-xl sm:text-2xl font-black text-slate-900 mt-1">{pendingCount}</p>
          </div>
          <div className="bg-white p-3.5 sm:p-4 rounded-2xl border border-slate-200/70 shadow-xs">
            <p className="text-[10px] sm:text-xs font-bold uppercase tracking-wider text-emerald-600">
              Captured Orders
            </p>
            <p className="text-xl sm:text-2xl font-black text-slate-900 mt-1">{capturedCount}</p>
          </div>
          <div className="bg-white p-3.5 sm:p-4 rounded-2xl border border-slate-200/70 shadow-xs">
            <p className="text-[10px] sm:text-xs font-bold uppercase tracking-wider text-rose-600">
              Blocked / Void
            </p>
            <p className="text-xl sm:text-2xl font-black text-slate-900 mt-1">{blockedCount}</p>
          </div>
        </section>

        {/* MOBILE VIEW: NATIVE FINTECH CARDS */}
        <section className="md:hidden flex flex-col gap-3">
          {rows.map((r) => (
            <div
              key={r.seq}
              className={`bg-white rounded-2xl p-4 border shadow-xs transition-all ${
                r.showActions
                  ? "border-amber-300 ring-2 ring-amber-500/10"
                  : "border-slate-200/80"
              }`}
            >
              <div className="flex items-center justify-between gap-2 pb-3 border-b border-slate-100">
                <span className="font-mono text-xs text-slate-600 bg-slate-100 px-2.5 py-1 rounded-md border border-slate-200 font-semibold">
                  {r.offerId}
                </span>
                {getStatusBadge(r.displayStatus, r.displayCode)}
              </div>

              <div className="flex items-baseline justify-between pt-3">
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-slate-400 font-bold">
                    Reservation ID
                  </p>
                  <p className="font-mono text-xs text-slate-600 mt-0.5">
                    {r.shortId.slice(0, 16)}...
                  </p>
                </div>
                <div className="text-right">
                  <p className="text-[10px] uppercase tracking-wider text-slate-400 font-bold">
                    Trusted Resolution
                  </p>
                  {r.total ? (
                    <p className="text-xl font-black text-slate-900">
                      ${r.total}{" "}
                      <span className="text-xs font-bold text-slate-400">{r.currency}</span>
                    </p>
                  ) : (
                    <p className="text-xs italic text-slate-400">Failed</p>
                  )}
                </div>
              </div>

              {r.showActions && (
                <div className="grid grid-cols-3 gap-2 mt-4 pt-3 border-t border-slate-100">
                  <button
                    onClick={() => handlePasskeyApprove(r.resId)}
                    disabled={isAuthenticating === r.resId}
                    className="col-span-2 text-xs font-bold bg-indigo-600 text-white py-3 px-4 rounded-xl shadow-md shadow-indigo-200 hover:bg-indigo-700 active:scale-[0.98] transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                  >
                    {isAuthenticating === r.resId ? "⏳ Verifying..." : "🛡️ Approve (Passkey)"}
                  </button>
                  <button
                    onClick={() => handleReject(r.resId)}
                    disabled={isAuthenticating === r.resId}
                    className="col-span-1 text-xs font-bold bg-white text-rose-600 border border-rose-200 py-3 px-3 rounded-xl hover:bg-rose-50 active:scale-[0.98] transition-all disabled:opacity-50"
                  >
                    Reject
                  </button>
                </div>
              )}
            </div>
          ))}

          {rows.length === 0 && (
            <div className="bg-white rounded-2xl p-12 text-center border border-slate-200/80 text-slate-400 text-sm font-medium">
              Awaiting Agentic Commerce Activity...
            </div>
          )}
        </section>

        {/* DESKTOP VIEW: FULL LEDGER TABLE */}
        <div className="hidden md:block bg-white rounded-2xl shadow-sm border border-slate-200/80 overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-[11px] text-slate-400 uppercase bg-slate-50/70 border-b border-slate-100 font-extrabold tracking-wider">
              <tr>
                <th className="px-6 py-4">Reservation ID</th>
                <th className="px-6 py-4">Agent Claim</th>
                <th className="px-6 py-4">Trusted Resolution</th>
                <th className="px-6 py-4">Enforcement & Biometrics</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((r) => (
                <tr key={r.seq} className="hover:bg-slate-50/60 transition-colors">
                  <td className="px-6 py-5 font-mono text-xs text-slate-500 font-medium">
                    {r.shortId}
                  </td>
                  <td className="px-6 py-5">
                    <span className="font-mono text-slate-700 bg-slate-100 px-2.5 py-1 rounded-md text-xs border border-slate-200 font-medium">
                      {r.offerId}
                    </span>
                  </td>
                  <td className="px-6 py-5">
                    {r.total ? (
                      <div className="flex items-baseline gap-1.5">
                        <span className="font-black text-slate-900 text-lg tracking-tight">
                          ${r.total}
                        </span>
                        <span className="text-[10px] text-slate-400 font-bold uppercase">
                          {r.currency}
                        </span>
                      </div>
                    ) : (
                      <span className="text-slate-400 italic text-xs">Failed</span>
                    )}
                  </td>
                  <td className="px-6 py-5">
                    <div className="flex items-center justify-between gap-4">
                      {getStatusBadge(r.displayStatus, r.displayCode)}

                      {r.showActions && (
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => handlePasskeyApprove(r.resId)}
                            disabled={isAuthenticating === r.resId}
                            className="text-xs font-bold bg-indigo-600 text-white px-4 py-2 rounded-xl shadow-sm shadow-indigo-200 hover:bg-indigo-700 transition-all cursor-pointer disabled:opacity-50 flex items-center gap-1.5"
                          >
                            {isAuthenticating === r.resId ? "⏳ Verifying..." : "🛡️ Approve (Passkey)"}
                          </button>
                          <button
                            onClick={() => handleReject(r.resId)}
                            disabled={isAuthenticating === r.resId}
                            className="text-xs font-bold bg-white text-rose-600 border border-rose-200 px-3.5 py-2 rounded-xl hover:bg-rose-50 transition-all cursor-pointer disabled:opacity-50"
                          >
                            Reject
                          </button>
                        </div>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-6 py-16 text-center text-slate-400 font-medium text-sm">
                    Awaiting Agentic Commerce Activity...
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </main>
  );
}