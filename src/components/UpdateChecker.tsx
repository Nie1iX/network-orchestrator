import { tr } from "../i18n";
import { useState } from "react";
import { check, Update } from "@tauri-apps/plugin-updater";
import { confirm, message } from "@tauri-apps/plugin-dialog";

export default function UpdateChecker() {
  const [checking, setChecking] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);

  const checkForUpdates = async () => {
    setChecking(true);
    try {
      const update = await check();
      if (update?.available) {
        const ok = await confirm(
          tr("New version {version} is available. Install now?", { version: String(update.version) }),
          { title: tr("Update available"), kind: "info" },
        );
        if (!ok) return;
        await installUpdate(update);
      } else {
        await message(tr("You are running the latest version."), {
          title: tr("No updates"),
          kind: "info",
        });
      }
    } catch (err) {
      await message(tr("Update check failed: {err}", { err: String(err) }), {
        title: tr("Update error"),
        kind: "error",
      });
    } finally {
      setChecking(false);
    }
  };

  const installUpdate = async (update: Update) => {
    setInstalling(true);
    setProgress("Downloading…");
    try {
      let downloaded = 0;
      let total = 0;
      await update.downloadAndInstall((event) => {
        switch (event.event) {
          case "Started":
            total = event.data.contentLength ?? 0;
            setProgress(`Downloading 0 / ${total} bytes`);
            break;
          case "Progress":
            downloaded += event.data.chunkLength;
            setProgress(`Downloading ${downloaded} / ${total} bytes`);
            break;
          case "Finished":
            setProgress("Installing…");
            break;
        }
      });
      setProgress("Installed. Restarting…");
      await relaunch();
    } catch (err) {
      await message(tr("Update install failed: {err}", { err: String(err) }), {
        title: tr("Update error"),
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
        onClick={checkForUpdates}
        disabled={checking || installing}
        title={tr("Check for updates")}
      >
        {checking ? tr("Checking…") : installing ? tr("Updating…") : tr("Check updates")}
      </button>
      {progress && <span className="update-progress">{progress}</span>}
    </div>
  );
}

async function relaunch() {
  const { relaunch } = await import("@tauri-apps/plugin-process");
  await relaunch();
}
