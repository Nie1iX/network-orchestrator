import { CloseIcon, PlusIcon } from "../../icons";
import { ConnectionSnippet } from "./sets";

interface SetsBarProps {
  snippets: ConnectionSnippet[];
  activeSnippetId: string | null;
  activeDirty: boolean;
  runningCount: number;
  onApply: (snippet: ConnectionSnippet) => void;
  onDelete: (id: string) => void;
  onUpdateActive: () => void;
  onSaveNew: () => void;
}

export default function SetsBar({
  snippets,
  activeSnippetId,
  activeDirty,
  runningCount,
  onApply,
  onDelete,
  onUpdateActive,
  onSaveNew,
}: SetsBarProps) {
  const activeSnippet =
    snippets.find((s) => s.id === activeSnippetId) ?? null;

  return (
    <div className="snippets-bar">
      <span className="snippets-label">Sets</span>
      {snippets.length === 0 && (
        <span className="snippets-hint">
          Save the running combination for one-click restore
        </span>
      )}
      <div className="snippets-chips">
        {snippets.map((snippet) => {
          const isActive = snippet.id === activeSnippetId;
          const isDirty = isActive && activeDirty;
          return (
            <div
              key={snippet.id}
              className={`snippet-chip ${isDirty ? "dirty" : isActive ? "active" : ""}`}
            >
              <button
                type="button"
                className="snippet-chip-apply"
                onClick={() => onApply(snippet)}
                title={
                  isDirty
                    ? "Connections have changed since this set was saved"
                    : `Switch to exactly these ${snippet.profileIds.length} connection${
                        snippet.profileIds.length === 1 ? "" : "s"
                      }`
                }
              >
                {snippet.name}
                <span className="snippet-chip-count">
                  {snippet.profileIds.length}
                </span>
              </button>
              <button
                type="button"
                className="snippet-chip-delete"
                onClick={() => onDelete(snippet.id)}
                title="Delete set"
              >
                <CloseIcon size={12} />
              </button>
            </div>
          );
        })}
        {activeSnippet && activeDirty && (
          <button
            type="button"
            className="snippet-chip-add"
            onClick={onUpdateActive}
            title={`Update "${activeSnippet.name}" to match the currently running connections`}
          >
            Update "{activeSnippet.name}"
          </button>
        )}
        <button
          type="button"
          className="snippet-chip-add"
          onClick={onSaveNew}
          disabled={runningCount === 0}
          title={
            runningCount === 0
              ? "Connect something first"
              : "Save the currently running connections as a set"
          }
        >
          <PlusIcon size={12} /> Save current
        </button>
      </div>
    </div>
  );
}
