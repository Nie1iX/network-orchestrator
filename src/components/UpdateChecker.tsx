import { useState } from "react";
import { check, Update } from "@tauri-apps/plugin-updater";
import { confirm, message } from "@tauri-apps/plugin-dialog";
import { useT } from "../i18n";

export default function UpdateChecker() {
  const t = useT();
  const [checking, setChecking] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);

  const checkForUpdates = async () => {
    setChecking(true);
    try {
      const update = await check();
      if (update?.available) {
        const ok = await confirm(
          t("update.available", { version: update.version }),
          { title: t("update.availableTitle"), kind: "info" },
        );
        if (!ok) return;
        await installUpdate(update);
      } else {
        await message(t("update.latest"), {
          title: t("update.noUpdates"),
          kind: "info",
        });
      }
    } catch (err) {
      await message(t("update.checkFailed", { err: String(err) }), {
        title: t("update.errorTitle"),
        kind: "error",
      });
    } finally {
      setChecking(false);
    }
  };

  const installUpdate = async (update: Update) => {
    setInstalling(true);
    setProgress(t("update.downloading"));
    try {
      let downloaded = 0;
      let total = 0;
      await update.downloadAndInstall((event) => {
        switch (event.event) {
          case "Started":
            total = event.data.contentLength ?? 0;
            setProgress(
              t("update.downloadProgress", { done: 0, total }),
            );
            break;
          case "Progress":
            downloaded += event.data.chunkLength;
            setProgress(
              t("update.downloadProgress", { done: downloaded, total }),
            );
            break;
          case "Finished":
            setProgress(t("update.installing"));
            break;
        }
      });
      setProgress(t("update.restarting"));
      await relaunch();
    } catch (err) {
      await message(t("update.installFailed", { err: String(err) }), {
        title: t("update.errorTitle"),
        kind: "error",
      });
    } finally {
      setInstalling(false);
      setProgress(null);
    }
  };

  return (
    <div className="update-checker">
      <button
        className="btn-sm"
        onClick={checkForUpdates}
        disabled={checking || installing}
        title={t("update.checkTitle")}
      >
        {checking
          ? t("common.checking")
          : installing
            ? t("update.updating")
            : t("update.check")}
      </button>
      {progress && <span className="update-progress">{progress}</span>}
    </div>
  );
}

async function relaunch() {
  const { relaunch } = await import("@tauri-apps/plugin-process");
  await relaunch();
}
