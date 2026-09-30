import {
  BackendExecutableSource,
  InterfaceCategory,
  TunnelBackend,
} from "../types";
import { TranslationKey } from "./index";

export const BACKEND_LABEL_KEYS: Record<TunnelBackend, TranslationKey> = {
  none: "backend.none",
  wireGuard: "backend.wireGuard",
  openVpn: "backend.openVpn",
  xray: "backend.xray",
};

export const SOURCE_LABEL_KEYS: Record<
  BackendExecutableSource,
  TranslationKey
> = {
  autoDetected: "backend.srcAuto",
  configured: "backend.srcConfigured",
  managed: "backend.srcManaged",
};

export const CATEGORY_LABEL_KEYS: Record<InterfaceCategory, TranslationKey> = {
  physical: "ifcat.physical",
  vpn: "ifcat.vpn",
  virtual: "ifcat.virtual",
  tunnel: "ifcat.tunnel",
  filter: "ifcat.filter",
  system: "ifcat.system",
};

export const CATEGORY_DESC_KEYS: Record<InterfaceCategory, TranslationKey> = {
  physical: "ifcat.desc.physical",
  vpn: "ifcat.desc.vpn",
  virtual: "ifcat.desc.virtual",
  tunnel: "ifcat.desc.tunnel",
  filter: "ifcat.desc.filter",
  system: "ifcat.desc.system",
};
