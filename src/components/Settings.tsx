import { useEffect, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import BackendStatus from "./BackendStatus";
import UpdateChecker from "./UpdateChecker";
import Page from "./Page";

export default function Settings() {
  const [version, setVersion] = useState<string | null>(null);

  useEffect(() => {
    getVersion().then(setVersion).catch(() => setVersion(null));
  }, []);

  return (
    <Page width="narrow">
      <h2>Settings</h2>

      <div className="settings-group">
        <div className="settings-group-title">Backend &amp; dependencies</div>
        <div className="settings-group-body">
          <BackendStatus />
        </div>
      </div>

      <div className="settings-group">
        <div className="settings-group-title">Updates</div>
        <div className="settings-group-body">
          <div className="settings-row">
            <div className="settings-row-main">
              <span className="settings-row-label">App updates</span>
              <span className="settings-row-sub">
                Check for and install new versions
              </span>
            </div>
            <UpdateChecker />
          </div>
        </div>
      </div>

      <div className="settings-group">
        <div className="settings-group-title">About</div>
        <div className="settings-group-body">
          <div className="settings-row">
            <div className="settings-row-main">
              <span className="settings-row-label">Network Manager</span>
              <span className="settings-row-sub">
                {version ? `Version ${version}` : "Loading version…"}
              </span>
            </div>
          </div>
        </div>
      </div>
    </Page>
  );
}
