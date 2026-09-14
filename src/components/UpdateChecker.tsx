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
          `New version ${update.version} is available. Install now?`,
          { title: "Update available", kind: "info" },
        );
        if (!ok) return;
        await installUpdate(update);
      } else {
        await message("You are running the latest version.", {
          title: "No updates",
          kind: "info",
        });
      }
    } catch (err) {
      await message(`Update check failed: ${err}`, {
        title: "Update error",
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
      await message(`Update install failed: ${err}`, {
        title: "Update error",
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
        title="Check for updates"
      >
        {checking ? "Checking…" : installing ? "Updating…" : "Check updates"}
      </button>
      {progress && <span className="update-progress">{progress}</span>}
    </div>
  );
}

async function relaunch() {
  const { relaunch } = await import("@tauri-apps/plugin-process");
  await relaunch();
}
