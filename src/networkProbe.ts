export type NetworkPathProbeStageName = "dns" | "route" | "https";
export type NetworkPathProbeOutcome = "healthy" | "failed" | "unknown";

export interface NetworkPathProbeStage {
  stage: NetworkPathProbeStageName;
  outcome: NetworkPathProbeOutcome;
  message: string;
  durationMs: number | null;
  interfaceName?: string | null;
  statusCode?: number | null;
}

export interface NetworkPathProbe {
  target: string;
  scope: "system" | "systemProxy";
  stages: NetworkPathProbeStage[];
}
