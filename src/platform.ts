import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { PlatformCapabilities } from "./types";

let cached: Promise<PlatformCapabilities> | null = null;

export function getPlatformCapabilities(): Promise<PlatformCapabilities> {
  if (!cached) {
    cached = invoke<PlatformCapabilities>("get_platform_capabilities").catch(
      (err) => {
        cached = null;
        throw err;
      }
    );
  }
  return cached;
}

/** Platform capabilities, or `null` while loading or if the query failed. */
export function usePlatformCapabilities(): PlatformCapabilities | null {
  const [caps, setCaps] = useState<PlatformCapabilities | null>(null);
  useEffect(() => {
    let active = true;
    getPlatformCapabilities()
      .then((value) => {
        if (active) setCaps(value);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, []);
  return caps;
}
