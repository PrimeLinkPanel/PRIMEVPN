import { z } from 'zod';

import { PortSchema } from '@/schemas/primitives';
import {
  RealityClientSettingsSchema,
  RealityStreamSettingsSchema,
} from '@/schemas/protocols/security/reality';
import {
  AlpnSchema,
  TlsClientSettingsSchema,
  TlsStreamSettingsSchema,
  UtlsFingerprintSchema,
} from '@/schemas/protocols/security/tls';

import { FinalMaskStreamSettingsSchema } from './finalmask';
import { SockoptStreamSettingsSchema } from './sockopt';
import { GrpcStreamSettingsSchema } from './grpc';
import { HttpUpgradeStreamSettingsSchema } from './httpupgrade';
import { KcpStreamSettingsSchema } from './kcp';
import { TcpStreamSettingsSchema } from './tcp';
import { WsStreamSettingsSchema } from './ws';
import { XHttpStreamSettingsSchema } from './xhttp';

// `forceTls` is the historical External Proxy switch. It remains on the wire
// so existing rows and older nodes keep working. New subscription profiles use
// `security`; generators fall back to forceTls when security is absent/same.
export const ExternalProxyForceTlsSchema = z.enum(['same', 'tls', 'none']);
export type ExternalProxyForceTls = z.infer<typeof ExternalProxyForceTlsSchema>;

export const SubscriptionProfileNetworkSchema = z.enum([
  'same',
  'tcp',
  'kcp',
  'ws',
  'grpc',
  'httpupgrade',
  'xhttp',
]);
export type SubscriptionProfileNetwork = z.infer<typeof SubscriptionProfileNetworkSchema>;

export const SubscriptionProfileSecuritySchema = z.enum([
  'same',
  'none',
  'tls',
  'reality',
]);
export type SubscriptionProfileSecurity = z.infer<typeof SubscriptionProfileSecuritySchema>;

export const SubscriptionProfileSubTypeSchema = z.enum(['raw', 'json', 'clash']);
export type SubscriptionProfileSubType = z.infer<typeof SubscriptionProfileSubTypeSchema>;

export const SubscriptionProfileMihomoIpVersionSchema = z.enum([
  'dual',
  'ipv4',
  'ipv6',
  'ipv4-prefer',
  'ipv6-prefer',
]);
export type SubscriptionProfileMihomoIpVersion = z.infer<typeof SubscriptionProfileMihomoIpVersionSchema>;

export const SubscriptionProfileVlessRouteSchema = z.preprocess(
  (val) => {
    if (typeof val !== 'string') return val;
    const trimmed = val.trim();
    return trimmed === '' ? undefined : trimmed;
  },
  z.string()
    .regex(
      /^(\d{1,5}(-\d{1,5})?)(\s*,\s*\d{1,5}(-\d{1,5})?)*$/,
      'pages.hosts.toasts.badVlessRoute',
    )
    .optional(),
);

// Client-facing TLS shape used in generated subscription outputs. When a profile
// owns a real runtime listener, its server certificate/private-key settings live
// separately under runtime.tlsSettings.
export const SubscriptionProfileTlsSettingsSchema = z.object({
  serverName: z.string().default(''),
  alpn: z.array(AlpnSchema).default([]),
  settings: TlsClientSettingsSchema.extend({
    allowInsecure: z.boolean().default(false),
  }).default({
    fingerprint: 'chrome',
    echConfigList: '',
    pinnedPeerCertSha256: [],
    verifyPeerCertByName: '',
    allowInsecure: false,
  }),
});
export type SubscriptionProfileTlsSettings = z.infer<typeof SubscriptionProfileTlsSettingsSchema>;

// Client-facing Reality shape used in generated subscription outputs. The
// listener private key, target and accepted names live separately under
// runtime.realitySettings when a real runtime endpoint is enabled.
export const SubscriptionProfileRealitySettingsSchema = z.object({
  serverNames: z.array(z.string()).default([]),
  shortIds: z.array(z.string()).default([]),
  settings: RealityClientSettingsSchema.default({
    publicKey: '',
    fingerprint: 'chrome',
    serverName: '',
    shortId: '',
    spiderX: '/',
    mldsa65Verify: '',
  }),
});
export type SubscriptionProfileRealitySettings = z.infer<typeof SubscriptionProfileRealitySettingsSchema>;

// Per-profile outbound Mux override used by JSON subscriptions. Absence means
// inherit the global subscription Mux setting; enabled=false explicitly turns
// Mux off for this profile.
export const SubscriptionProfileMuxSchema = z.object({
  enabled: z.boolean().default(true),
  concurrency: z.number().int().default(8),
  xudpConcurrency: z.number().int().default(16),
  xudpProxyUDP443: z.enum(['reject', 'allow', 'skip']).default('reject'),
});
export type SubscriptionProfileMux = z.infer<typeof SubscriptionProfileMuxSchema>;

// Client/dialer-side Sockopt only. Server/listener fields are stripped.
export const SubscriptionProfileSockoptSchema =
  SockoptStreamSettingsSchema.omit({
    acceptProxyProtocol: true,
    V6Only: true,
    trustedXForwardedFor: true,
  });
export type SubscriptionProfileSockopt =
  typeof SubscriptionProfileSockoptSchema._output;

// Hidden server-side metadata for the automatically compiled profile listener.
// Enablement, mode, listen and port are derived from the active modern profile
// and its logical parent; deprecated copies remain readable only for migration.
export const SubscriptionProfileRuntimeSchema = z.object({
  id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/).optional(),
  flow: z.string().optional(),
  tlsSettings: TlsStreamSettingsSchema.optional(),
  realitySettings: RealityStreamSettingsSchema.optional(),
  sockopt: SockoptStreamSettingsSchema.optional(),
  // Deprecated topology controls. Save normalization strips these before the
  // wire payload; keeping them readable preserves existing records.
  enabled: z.boolean().optional(),
  mode: z.enum(['direct', 'shared']).optional(),
  listen: z.string().optional(),
  port: PortSchema.optional(),
});
export type SubscriptionProfileRuntime = z.infer<typeof SubscriptionProfileRuntimeSchema>;

// One inbound can advertise several complete client-side connection profiles.
// Protocol and client identity remain owned by the parent inbound; address,
// port, transport, security and client-only stream settings can be overridden.
export const ExternalProxyEntrySchema = z.object({
  enabled: z.boolean().optional(),
  remark: z.string().default(''),
  dest: z.string().default(''),
  port: PortSchema.default(443),

  network: SubscriptionProfileNetworkSchema.optional(),
  security: SubscriptionProfileSecuritySchema.optional(),

  tcpSettings: TcpStreamSettingsSchema.optional(),
  kcpSettings: KcpStreamSettingsSchema.optional(),
  wsSettings: WsStreamSettingsSchema.optional(),
  grpcSettings: GrpcStreamSettingsSchema.optional(),
  httpupgradeSettings: HttpUpgradeStreamSettingsSchema.optional(),
  xhttpSettings: XHttpStreamSettingsSchema.optional(),
  tlsSettings: SubscriptionProfileTlsSettingsSchema.optional(),
  realitySettings: SubscriptionProfileRealitySettingsSchema.optional(),
  finalmask: FinalMaskStreamSettingsSchema.optional(),
  mux: SubscriptionProfileMuxSchema.optional(),
  sockopt: SubscriptionProfileSockoptSchema.optional(),
  // Per-profile client flow. Runtime listener compilation and every
  // subscription format consume this same value.
  flow: z.string().optional(),
  runtime: SubscriptionProfileRuntimeSchema.optional(),

  // PRIMEVPN phase-1 parity with Managed Hosts.
  excludeFromSubTypes: z.array(SubscriptionProfileSubTypeSchema).optional(),
  vlessRoute: SubscriptionProfileVlessRouteSchema,
  mihomoIpVersion: z.preprocess(
    (val) => (val === '' ? undefined : val),
    SubscriptionProfileMihomoIpVersionSchema.optional(),
  ),
  mihomoX25519: z.boolean().optional(),
  shuffleHost: z.boolean().optional(),

  // Legacy External Proxy fields. They are still read and emitted so old
  // configurations remain byte-compatible until a later explicit migration.
  forceTls: ExternalProxyForceTlsSchema.default('same'),
  sni: z.string().optional(),
  fingerprint: z.preprocess(
    (val) => (val === '' ? undefined : val),
    UtlsFingerprintSchema.optional(),
  ),
  alpn: z.array(AlpnSchema).optional(),
  pinnedPeerCertSha256: z.array(z.string()).optional(),
  verifyPeerCertByName: z.string().optional(),
  overrideSniFromAddress: z.boolean().optional(),
  keepSniBlank: z.boolean().optional(),
  echConfigList: z.string().optional(),
  allowInsecure: z.boolean().optional(),
});
export type ExternalProxyEntry = z.infer<typeof ExternalProxyEntrySchema>;
