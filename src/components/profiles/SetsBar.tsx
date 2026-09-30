import { CloseIcon, PlusIcon } from "../../icons";
import { pluralize, useT } from "../../i18n";
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
  const t = useT();
  const activeSnippet =
    snippets.find((s) => s.id === activeSnippetId) ?? null;

  return (
    <div className="snippets-bar">
      <span className="snippets-label">{t("sets.label")}</span>
      {snippets.length === 0 && (
        <span className="snippets-hint">{t("sets.hint")}</span>
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
                    ? t("sets.dirtyTitle")
                    : t("sets.applyTitle", {
                        n: snippet.profileIds.length,
                        unit: pluralize(
                          snippet.profileIds.length,
                          ["подключение", "подключения", "подключений"],
                          ["connection", "connections"],
                        ),
                      })
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
                title={t("sets.deleteTitle")}
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
            title={t("sets.updateTitle", { name: activeSnippet.name })}
          >
            {t("sets.updateActive", { name: activeSnippet.name })}
          </button>
        )}
        <button
          type="button"
          className="snippet-chip-add"
          onClick={onSaveNew}
          disabled={runningCount === 0}
          title={
            runningCount === 0 ? t("sets.connectFirst") : t("sets.saveTitle")
          }
        >
          <PlusIcon size={12} /> {t("sets.saveCurrent")}
        </button>
      </div>
    </div>
  );
}
