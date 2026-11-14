import type { ProfileDocument } from "./profileDocument";
import type { SubscriptionEndpointInfo } from "./types";

export interface ProfileEditorSession {
  profileId: string;
  document: ProfileDocument | null;
  revision: string | null;
  runningRevision: string | null;
  endpoints: SubscriptionEndpointInfo[];
  dirty: boolean;
  busy: boolean;
}

export interface NetworkEditorState {
  dirty: boolean;
  busy: boolean;
}
