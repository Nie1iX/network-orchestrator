import { useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { confirm } from "@tauri-apps/plugin-dialog";
import Modal from "../Modal";
import Skeleton from "../ui/Skeleton";
import { ProfileGraph } from "./ProfileGraph";
import { tr, useLanguage } from "../../i18n";
import { buildProfileGraph, documentDiff, parseProfileDocument, type DocumentIssue, type ProfileDocument } from "../../profileDocument";
import { locateDocumentPointer } from "../../profileDocumentLocation";
import type { NetworkInterface, SubscriptionEndpointInfo, TunnelStatus } from "../../types";
import "./ProfileDocumentEditor.css";

interface EditorSnapshot {
  document: ProfileDocument;
  revision: string;
  endpoints: SubscriptionEndpointInfo[];
  running: boolean;
  runningRevision: string | null;
}
interface EditorPreview {
  valid: boolean;
  issues: DocumentIssue[];
  daemonValidated: boolean;
  changedPaths: string[];
  requiresReconnect: boolean;
}
interface Props {
  profileId: string;
  status: TunnelStatus | undefined;
  interfaces: NetworkInterface[];
  onClose: () => void;
  onSaved: (applied?: boolean) => Promise<void>;
}

export default function ProfileDocumentEditor({ profileId, status, interfaces, onClose, onSaved }: Props) {
  useLanguage();
  const [snapshot, setSnapshot] = useState<EditorSnapshot | null>(null);
  const [draft, setDraft] = useState<{ text: string; lastValid: ProfileDocument } | null>(null);
  const [mode, setMode] = useState<"graph" | "json" | "split">("graph");
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [preview, setPreview] = useState<{ text: string; revision: string; result: EditorPreview } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reload, setReload] = useState(0);
  const [savedPaths, setSavedPaths] = useState<string[]>([]);
  const [appliedRevision, setAppliedRevision] = useState<string | null>(null);
  const [needsApply, setNeedsApply] = useState(false);
  const [confirmApply, setConfirmApply] = useState(false);
  const textInput = useRef<HTMLTextAreaElement>(null);
  const pendingTextJump = useRef(false);
  const text = draft?.text ?? "";
  const parsed = useMemo(() => parseProfileDocument(text), [text]);
  const graph = useMemo(() => draft && snapshot ? buildProfileGraph(draft.lastValid, snapshot.endpoints) : null, [draft, snapshot]);
  const dirty = Boolean(snapshot && text !== JSON.stringify(snapshot.document, null, 2));
  const currentPreview = preview?.text === text && preview.revision === snapshot?.revision ? preview.result : null;
  const issues = [...parsed.issues, ...(graph?.issues ?? []), ...(currentPreview?.issues ?? [])];
  const hasErrors = issues.some((issue) => issue.severity === "error");
  const isRunning = status ? status.state === "running" : snapshot?.running ?? false;

  useEffect(() => {
    let cancelled = false;
    setError(null);
    invoke<EditorSnapshot>("get_profile_document", { id: profileId }).then((value) => {
      if (cancelled) return;
      setSnapshot(value);
      setDraft({ text: JSON.stringify(value.document, null, 2), lastValid: value.document });
      setAppliedRevision(value.runningRevision);
      setPreview(null);
      setSavedPaths([]);
      setNeedsApply(false);
      setSelectedPath("/profile");
      setConfirmApply(false);
    }).catch((failure: unknown) => { if (!cancelled) setError(String(failure)); });
    return () => { cancelled = true; };
  }, [profileId, reload]);

  useEffect(() => {
    if (!pendingTextJump.current || !selectedPath || mode === "graph" || !draft) return;
    const range = locateDocumentPointer(draft.text, selectedPath);
    if (range && textInput.current) {
      textInput.current.focus();
      textInput.current.setSelectionRange(range.start, range.end);
      pendingTextJump.current = false;
    }
  }, [selectedPath, mode]);

  const updateText = (next: string) => {
    const result = parseProfileDocument(next);
    setDraft((previous) => previous ? { text: next, lastValid: result.document ?? previous.lastValid } : previous);
    setPreview(null);
    setError(null);
    setConfirmApply(false);
  };
  const selectTextPath = (path: string) => {
    pendingTextJump.current = true;
    setSelectedPath(path);
    if (mode === "graph") setMode("split");
    const range = locateDocumentPointer(text, path);
    if (range && textInput.current) {
      textInput.current.focus();
      textInput.current.setSelectionRange(range.start, range.end);
      pendingTextJump.current = false;
    }
  };
  const close = async () => {
    if (busy) return;
    if (!dirty || await confirm(tr("Discard unsaved profile changes?"), { title: tr("Profile constructor"), kind: "warning" })) onClose();
  };
  const validate = async () => {
    if (!snapshot || !parsed.document || busy) return;
    setBusy(true);
    setError(null);
    setConfirmApply(false);
    try {
      const result = await invoke<EditorPreview>("preview_profile_document", { id: profileId, document: parsed.document, expectedRevision: snapshot.revision });
      setPreview({ text, revision: snapshot.revision, result });
    } catch (failure) { setError(String(failure)); }
    finally { setBusy(false); }
  };
  const save = async () => {
    if (!snapshot || !parsed.document || !currentPreview?.valid || hasErrors || busy) return;
    setBusy(true);
    setError(null);
    try {
      const saved = await invoke<EditorSnapshot>("save_profile_document", { id: profileId, document: parsed.document, expectedRevision: snapshot.revision });
      const paths = documentDiff(snapshot.document, saved.document);
      const normalized = JSON.stringify(saved.document, null, 2);
      setSnapshot(saved);
      setDraft({ text: normalized, lastValid: saved.document });
      setSavedPaths((previous) => [...new Set([...previous, ...paths])]);
      setNeedsApply((previous) => previous || isRunning && paths.length > 0);
      setPreview({ text: normalized, revision: saved.revision, result: { ...currentPreview, changedPaths: paths } });
      setConfirmApply(false);
      await onSaved();
    } catch (failure) { setError(String(failure)); }
    finally { setBusy(false); }
  };
  const apply = async () => {
    if (!snapshot || dirty || !currentPreview?.valid || hasErrors || busy) return;
    setBusy(true);
    setError(null);
    try {
      const result = await invoke<TunnelStatus>("apply_profile_document", { id: profileId, expectedRevision: snapshot.revision });
      if (result.state !== "running") throw new Error(result.message ?? tr("The connection did not start. The saved profile and draft were retained."));
      setAppliedRevision(snapshot.revision);
      setNeedsApply(false);
      setSavedPaths([]);
      setConfirmApply(false);
      await onSaved(true);
    } catch (failure) { setError(String(failure)); }
    finally { setBusy(false); }
  };

  return <Modal open title={tr("Profile constructor")} maxWidth="min(1600px, 96vw)" onClose={() => { void close(); }} footer={<>
    <span className="profile-editor-footer-note">{busy ? tr("Working…") : tr("Saving never reconnects the tunnel.")}</span>
    <button type="button" disabled={busy} onClick={() => { void close(); }}>{tr("Close")}</button>
    <button type="button" disabled={busy || !parsed.document || (graph?.issues.some((issue) => issue.severity === "error") ?? true)} onClick={() => { void validate(); }}>{tr("Check draft")}</button>
    <button type="button" className="btn-primary" disabled={busy || !dirty || !currentPreview?.valid || hasErrors} onClick={() => { void save(); }}>{tr("Save profile")}</button>
  </>}>
    {error && <div className="save-notice" role="alert">{error}{!snapshot && <button type="button" onClick={() => setReload((value) => value + 1)}>{tr("Retry")}</button>}</div>}
    {!snapshot || !draft ? !error && <Skeleton height="320px" /> : <div className="profile-document-editor">
      <div className="profile-editor-toolbar">
        <div className="segmented" aria-label={tr("Editor view")}>
          {([ ["graph", "Nodes"], ["json", "JSON"], ["split", "Nodes and JSON"] ] as const).map(([value, label]) => <button key={value} type="button" className="btn-sm" aria-pressed={mode === value} onClick={() => setMode(value)}>{tr(label)}</button>)}
        </div>
        <button type="button" className="btn-sm" disabled={busy} onClick={async () => {
          if (!dirty || await confirm(tr("Discard unsaved profile changes?"), { kind: "warning" })) setReload((value) => value + 1);
        }}>{tr("Reload saved profile")}</button>
      </div>
      <dl className="profile-editor-revisions">
        <div><dt>{tr("Draft")}</dt><dd>{dirty ? tr("Unsaved changes") : tr("Matches saved profile")}</dd></div>
        <div><dt>{tr("Saved revision")}</dt><dd><code>{snapshot.revision.slice(0, 12)}</code></dd></div>
        <div><dt>{tr("Running revision")}</dt><dd>{isRunning ? appliedRevision ? <code>{appliedRevision.slice(0, 12)}</code> : tr("Unknown — reconnect to apply the saved profile") : tr("Not running")}</dd></div>
      </dl>
      <p className="row-hint">{tr("JSON and nodes edit the same profile. Node positions do not change rule order. Formatting is normalized by node edits and saving.")}</p>
      {!parsed.document && <div className="save-notice" role="alert">{tr("Invalid JSON: the graph shows the last valid draft and cannot be edited or saved.")}</div>}
      <div className={`profile-editor-workspace profile-editor-${mode}`}>
        <div className="profile-editor-graph" hidden={mode === "json"}><ProfileGraph document={draft.lastValid} endpoints={snapshot.endpoints} issues={[...parsed.issues, ...(currentPreview?.issues ?? [])]} selectedPath={selectedPath} onSelect={setSelectedPath} onChange={(document) => updateText(JSON.stringify(document, null, 2))} disabled={busy || !parsed.document} /></div>
        {mode !== "graph" && <section className="profile-editor-source">
          <div className="profile-editor-source-head"><label htmlFor="profile-document-json">{tr("Profile JSON")}</label>{selectedPath && <code>{selectedPath}</code>}</div>
          <textarea ref={textInput} id="profile-document-json" aria-label={tr("Profile JSON")} spellCheck={false} value={text} disabled={busy} onChange={(event) => updateText(event.target.value)} />
        </section>}
      </div>
      {selectedPath && mode === "graph" && <button type="button" className="btn-sm" onClick={() => selectTextPath(selectedPath)}>{tr("Show selected node in JSON")}</button>}
      {issues.length > 0 && <section className="profile-editor-issues" aria-label={tr("Validation issues")}>
        {issues.map((issue, index) => <div key={`${issue.path}-${index}`} className={issue.severity === "error" ? "save-notice" : "runtime-notice"} role={issue.severity === "error" ? "alert" : undefined}>
          <button type="button" className="btn-ghost btn-sm mono" onClick={() => selectTextPath(issue.path)}>{issue.path || "/"}</button><span>{tr(issue.message)}</span>
        </div>)}
      </section>}
      {currentPreview && <div className="runtime-notice" role="status">{currentPreview.valid ? currentPreview.daemonValidated ? tr("The daemon accepted the generated configuration.") : draft.lastValid.profile.backend === "mihomo" ? tr("Local profile validation passed; privileged validation was not performed.") : tr("Local profile validation passed. Privileged Xray validation was not performed for this backend.") : tr("The draft was rejected. Nothing was saved or reconnected.")}</div>}
      <details className="profile-editor-diff"><summary>{tr("Changed JSON paths")} ({(currentPreview?.changedPaths ?? documentDiff(snapshot.document, draft.lastValid)).length})</summary>
        <ul>{(currentPreview?.changedPaths ?? documentDiff(snapshot.document, draft.lastValid)).map((path) => <li key={path}><button type="button" className="btn-ghost btn-sm mono" onClick={() => selectTextPath(path)}>{path}</button></li>)}</ul>
      </details>
      <details className="profile-editor-observed"><summary>{tr("Observed network — read-only")}</summary><p className="row-hint">{tr("Interfaces are observed runtime state, not editable profile nodes.")}</p>
        <ul>{interfaces.filter((iface) => iface.category !== "system").map((iface) => <li key={iface.ifIndex}><code>{iface.name}</code> · {iface.state}</li>)}</ul>
        {status?.interfaceName && <p><code>{status.interfaceName}</code> · {tr("Current profile interface")}</p>}
      </details>
      <div className="profile-editor-apply">
        <div>{needsApply ? <strong>{tr("Saved changes require an explicit reconnect.")}</strong> : tr("Apply the saved profile only when you are ready to change the connection.")}</div>
        {!confirmApply ? <button type="button" disabled={busy || dirty || !currentPreview?.valid || hasErrors} onClick={() => setConfirmApply(true)}>{isRunning ? tr("Review reconnect") : tr("Review connection")}</button> : <div className="save-notice">
          <p>{tr("This explicitly stops the current profile if running, then connects its saved revision. Existing connections may be interrupted.")}</p>
          {!appliedRevision && isRunning && <p>{tr("The running revision is unknown; an exact diff against the running configuration is unavailable.")}</p>}
          <ul>{savedPaths.map((path) => <li key={path}><code>{path}</code></li>)}</ul>
          <button type="button" disabled={busy} onClick={() => { void apply(); }}>{isRunning ? tr("Reconnect saved profile") : tr("Connect saved profile")}</button>
          <button type="button" disabled={busy} onClick={() => setConfirmApply(false)}>{tr("Cancel")}</button>
        </div>}
      </div>
    </div>}
  </Modal>;
}
