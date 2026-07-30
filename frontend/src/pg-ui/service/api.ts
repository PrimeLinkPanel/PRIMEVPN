import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { HttpUtil } from '@/utils';

type ApiMsg<T = unknown> = {
  success?: boolean;
  msg?: string;
  obj?: T;
};

const JSON_OPTIONS = { headers: { 'Content-Type': 'application/json' } } as const;

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function toNumber(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : Number(value || 0);
}

function toBool(value: unknown): boolean {
  return value === true || value === 'true' || value === 1;
}

function toString(value: unknown): string {
  return typeof value === 'string' ? value : String(value ?? '');
}

async function apiGet<T = unknown>(url: string): Promise<T> {
  const msg = await HttpUtil.get(url, undefined, { silent: true }) as ApiMsg<T>;
  if (!msg?.success) throw new Error(msg?.msg || `Request failed: ${url}`);
  return msg.obj as T;
}

async function apiPost<T = unknown>(url: string, payload?: unknown): Promise<T> {
  const msg = await HttpUtil.post(url, payload, JSON_OPTIONS) as ApiMsg<T>;
  if (!msg?.success) throw new Error(msg?.msg || `Request failed: ${url}`);
  return msg.obj as T;
}

export type RolePermissions = Record<string, unknown>;

export interface RoleLimits {
  max_users?: number | string | null;
  data_limit_min?: number | string | null;
  data_limit_max?: number | string | null;
  expire_min?: number | string | null;
  expire_max?: number | string | null;
  expire_days_min?: number | string | null;
  expire_days_max?: number | string | null;
  download_mbps_min?: number | string | null;
  download_mbps_max?: number | string | null;
  upload_mbps_min?: number | string | null;
  upload_mbps_max?: number | string | null;
  minDownloadMbps?: number | string | null;
  maxDownloadMbps?: number | string | null;
  minUploadMbps?: number | string | null;
  maxUploadMbps?: number | string | null;
  [key: string]: unknown;
}

export interface RoleFeatures {
  can_use_reset_strategy?: boolean;
  can_use_next_plan?: boolean;
  blockLimitedAdmins?: boolean;
  disconnectUsersWhenLimited?: boolean;
  disconnectUsersWhenDisabled?: boolean;
  [key: string]: unknown;
}

export interface RoleAccess {
  allowed_inbound_ids?: number[] | null;
  allowedGroupIds?: number[] | null;
  allowed_group_ids?: number[] | null;
  [key: string]: unknown;
}

export interface HWIDSettings {
  mode?: string;
  enabled?: boolean;
  forced?: boolean;
  fallback_limit?: number | string | null;
  min_limit?: number | string | null;
  max_limit?: number | string | null;
  [key: string]: unknown;
}

export interface AdminRoleResponse {
  id: number;
  name: string;
  slug?: string;
  is_builtin: boolean;
  is_owner: boolean;
  builtIn: boolean;
  ownerRole: boolean;
  permissions?: RolePermissions;
  limits?: RoleLimits;
  features?: RoleFeatures;
  access?: RoleAccess;
  hwid?: HWIDSettings;
  created_at?: string | number;
  updated_at?: string | number;
  [key: string]: unknown;
}

export interface AdminDetails {
  id: number;
  username: string;
  status: 'active' | 'disabled' | string;
  is_disabled?: boolean;
  role?: AdminRoleResponse;
  role_id?: number;
  data_limit?: number | null;
  used_traffic?: number;
  lifetime_used_traffic?: number;
  total_users?: number;
  telegram_id?: string | number;
  discord_webhook?: string;
  support_url?: string;
  profile_title?: string;
  sub_domain?: string;
  sub_template?: string;
  note?: string;
  notification_enable?: unknown;
  permission_overrides?: RoleLimits;
  created_at?: string | number;
  updated_at?: string | number;
  [key: string]: unknown;
}

export enum Period {
  hour = 'hour',
  day = 'day',
}

export interface SystemResourceStats {
  version?: string;
  currentVersion?: string;
  [key: string]: unknown;
}

export interface AdminsListResponse {
  admins: AdminDetails[];
  data: AdminDetails[];
  items: AdminDetails[];
  total: number;
  total_count: number;
  active: number;
  disabled: number;
  limited: number;
  page: number;
  size: number;
}

function normalizeRole(value: unknown): AdminRoleResponse {
  const row = asRecord(value);
  const builtIn = toBool(row.builtIn ?? row.is_builtin);
  const ownerRole = toBool(row.ownerRole ?? row.is_owner);
  return {
    ...row,
    id: toNumber(row.id),
    name: toString(row.name),
    slug: toString(row.slug),
    is_builtin: builtIn,
    is_owner: ownerRole,
    builtIn,
    ownerRole,
    permissions: asRecord(row.permissions),
    limits: asRecord(row.limits) as RoleLimits,
    features: asRecord(row.features) as RoleFeatures,
    access: asRecord(row.access) as RoleAccess,
    created_at: row.createdAt === undefined ? toNumber(row.created_at) : toNumber(row.createdAt),
    updated_at: row.updatedAt === undefined ? toNumber(row.updated_at) : toNumber(row.updatedAt),
  };
}

function normalizeAdmin(value: unknown): AdminDetails {
  const row = asRecord(value);
  const role = normalizeRole({
    id: row.roleId ?? row.role_id,
    name: row.roleName ?? row.role_name,
    slug: row.roleSlug ?? row.role_slug,
    is_owner: row.roleSlug === 'owner',
  });

  const status = toString(row.status) || (toBool(row.is_disabled) ? 'disabled' : 'active');

  return {
    ...row,
    id: toNumber(row.id),
    username: toString(row.username),
    status,
    is_disabled: status === 'disabled',
    role,
    role_id: toNumber(row.roleId ?? row.role_id),
    data_limit: row.dataLimit === undefined ? toNumber(row.data_limit) : toNumber(row.dataLimit),
    used_traffic: row.usedBytes === undefined ? toNumber(row.used_traffic) : toNumber(row.usedBytes),
    lifetime_used_traffic: row.lifetimeUsedTraffic === undefined ? toNumber(row.lifetime_used_traffic) : toNumber(row.lifetimeUsedTraffic),
    total_users: row.totalUsers === undefined ? toNumber(row.total_users) : toNumber(row.totalUsers),
    telegram_id: toString(row.telegramId ?? row.telegram_id),
    discord_webhook: toString(row.discordWebhook ?? row.discord_webhook),
    support_url: toString(row.supportUrl ?? row.support_url),
    profile_title: toString(row.profileTitle ?? row.profile_title),
    sub_domain: toString(row.subscriptionDomain ?? row.sub_domain),
    sub_template: toString(row.subscriptionTemplatePath ?? row.sub_template),
    note: toString(row.note),
    notification_enable: row.notificationFilters ?? row.notification_enable,
    permission_overrides: asRecord(row.permissionOverrides ?? row.permission_overrides) as RoleLimits,
    created_at: row.createdAt === undefined ? toNumber(row.created_at) : toNumber(row.createdAt),
    updated_at: row.updatedAt === undefined ? toNumber(row.updated_at) : toNumber(row.updatedAt),
  };
}

function pgAdminToPRIMEVPNPayload(data: Record<string, unknown>): Record<string, unknown> {
  return {
    username: toString(data.username).trim(),
    password: toString(data.password).trim(),
    roleId: toNumber(data.role_id ?? data.roleId),
    status: toString(data.status || (toBool(data.is_disabled) ? 'disabled' : 'active')) || 'active',
    dataLimit: data.data_limit == null ? 0 : toNumber(data.data_limit),
    telegramId: toString(data.telegram_id),
    discordWebhook: toString(data.discord_webhook),
    supportUrl: toString(data.support_url),
    profileTitle: toString(data.profile_title),
    subscriptionDomain: toString(data.sub_domain),
    subscriptionTemplatePath: toString(data.sub_template),
    note: toString(data.note),
    notificationFilters: data.notification_enable ?? {},
    permissionOverrides: data.permission_overrides ?? {},
  };
}

function pgRoleToPRIMEVPNPayload(data: Record<string, unknown>): Record<string, unknown> {
  return {
    name: toString(data.name).trim(),
    permissions: data.permissions ?? {},
    limits: data.limits ?? {},
    features: data.features ?? {},
    access: data.access ?? {},
  };
}

async function fetchAdmins(): Promise<AdminDetails[]> {
  const rows = await apiGet<unknown>('/panel/api/admins/list');
  return Array.isArray(rows) ? rows.map(normalizeAdmin) : [];
}

async function fetchRoles(): Promise<AdminRoleResponse[]> {
  const rows = await apiGet<unknown>('/panel/api/admin-roles/list');
  return Array.isArray(rows) ? rows.map(normalizeRole) : [];
}

function extractQueryOptions(args: unknown[]): Record<string, unknown> {
  for (const arg of args) {
    const row = asRecord(arg);
    if (row.query && typeof row.query === 'object') return row.query as Record<string, unknown>;
  }
  return {};
}

export const getGetAdminsQueryKey = (...args: unknown[]) => ['pg-ui', 'admins', ...args];
export const getGetRolesQueryKey = (...args: unknown[]) => ['pg-ui', 'roles', ...args];
export const getGetRolesSimpleQueryKey = (...args: unknown[]) => ['pg-ui', 'roles-simple', ...args];
export const getGetAllGroupsQueryKey = (...args: unknown[]) => ['pg-ui', 'groups', ...args];
export const getGetUserTemplatesSimpleQueryKey = (...args: unknown[]) => ['pg-ui', 'templates-simple', ...args];
export const getGetSystemResourceStatsQueryKey = (...args: unknown[]) => ['pg-ui', 'system-resource-stats', ...args];

export function useGetSystemResourceStats(...args: unknown[]) {
  const queryOptions = extractQueryOptions(args);
  return useQuery<SystemResourceStats>({
    queryKey: getGetSystemResourceStatsQueryKey(args),
    queryFn: async () => apiGet<SystemResourceStats>('/panel/api/server/status'),
    ...(queryOptions as object),
  });
}


export function useGetAdmins(...args: unknown[]) {
  const queryOptions = extractQueryOptions(args);
  return useQuery<AdminsListResponse>({
    queryKey: getGetAdminsQueryKey(args),
    queryFn: async () => {
      const admins = await fetchAdmins();
        const active = admins.filter(admin => (admin.status || (admin.is_disabled ? 'disabled' : 'active')) !== 'disabled').length;
        const disabled = admins.filter(admin => (admin.status || (admin.is_disabled ? 'disabled' : 'active')) === 'disabled').length;
        const limited = admins.filter(admin => typeof admin.data_limit === 'number' && admin.data_limit > 0).length;
      return {
        admins,
        data: admins,
        items: admins,
        total: admins.length,
        total_count: admins.length,
          active,
          disabled,
          limited,
        page: 1,
        size: admins.length,
      };
    },
    ...(queryOptions as object),
  });
}

export function useGetRoles(...args: unknown[]) {
  const queryOptions = extractQueryOptions(args);
  return useQuery({
    queryKey: getGetRolesQueryKey(args),
    queryFn: async () => {
      const roles = await fetchRoles();
      return {
        roles,
        data: roles,
        items: roles,
        total: roles.length,
      };
    },
    ...(queryOptions as object),
  });
}

export function useGetRolesSimple(...args: unknown[]) {
  const queryOptions = extractQueryOptions(args);
  return useQuery({
    queryKey: getGetRolesSimpleQueryKey(args),
    queryFn: async () => {
      const roles = await fetchRoles();
      return {
        roles,
        data: roles,
        items: roles,
        total: roles.length,
      };
    },
    ...(queryOptions as object),
  });
}

export function useGetAllGroups(...args: unknown[]) {
  const queryOptions = extractQueryOptions(args);
  return useQuery({
    queryKey: getGetAllGroupsQueryKey(args),
    queryFn: async () => ({ groups: [], data: [], items: [], total: 0 }),
    ...(queryOptions as object),
  });
}

export function useGetUserTemplatesSimple(...args: unknown[]) {
  const queryOptions = extractQueryOptions(args);
  return useQuery({
    queryKey: getGetUserTemplatesSimpleQueryKey(args),
    queryFn: async () => ({ templates: [], data: [], items: [], total: 0 }),
    ...(queryOptions as object),
  });
}

export function useCreateAdmin() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (arg: unknown) => {
      const input = asRecord(arg);
        const data = asRecord(input.data ?? arg);
      const created = await apiPost('/panel/api/admins/add', pgAdminToPRIMEVPNPayload(data));
      return normalizeAdmin(created ?? data);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['pg-ui', 'admins'] }),
  });
}

export function useModifyAdminById() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (arg: unknown) => {
      const input = asRecord(arg);
        const adminId = toNumber(input.adminId ?? input.id);
      const data = asRecord(input.data ?? input.payload ?? arg);
      const status = toString(data.status);
      const roleId = toNumber(data.role_id ?? data.roleId);
      const hasUsername = toString(data.username).trim() !== '';

      if (!hasUsername && roleId <= 0 && (status === 'active' || status === 'disabled')) {
        await apiPost(`/panel/api/admins/${status === 'disabled' ? 'disable' : 'enable'}/${adminId}`);
        const updated = await apiGet(`/panel/api/admins/get/${adminId}`);
        return normalizeAdmin(updated ?? { ...data, id: adminId, status });
      }

      const existing = normalizeAdmin(await apiGet(`/panel/api/admins/get/${adminId}`));
      const merged = {
        ...existing,
        ...data,
        username: hasUsername ? toString(data.username).trim() : existing.username,
        role_id: roleId > 0 ? roleId : existing.role_id,
        status: status || existing.status || 'active',
        data_limit: data.data_limit === undefined && data.dataLimit === undefined
          ? existing.data_limit
          : data.data_limit ?? data.dataLimit,
        telegram_id: data.telegram_id ?? existing.telegram_id,
        discord_webhook: data.discord_webhook ?? existing.discord_webhook,
        support_url: data.support_url ?? existing.support_url,
        profile_title: data.profile_title ?? existing.profile_title,
        sub_domain: data.sub_domain ?? existing.sub_domain,
        sub_template: data.sub_template ?? existing.sub_template,
        note: data.note ?? existing.note,
        notification_enable: data.notification_enable ?? existing.notification_enable,
        permission_overrides: data.permission_overrides ?? existing.permission_overrides,
      };

      const updated = await apiPost(`/panel/api/admins/update/${adminId}`, pgAdminToPRIMEVPNPayload(merged));
      return normalizeAdmin(updated ?? { ...merged, id: adminId });
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['pg-ui', 'admins'] }),
  });
}

export function useRemoveAdminById() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (arg: unknown) => {
      const input = asRecord(arg);
        const adminId = toNumber(input.adminId ?? input.id ?? arg);
      await apiPost(`/panel/api/admins/del/${adminId}`);
      return { id: adminId };
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['pg-ui', 'admins'] }),
  });
}

export function useResetAdminUsageById() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (arg: unknown) => {
      const input = asRecord(arg);
        const adminId = toNumber(input.adminId ?? input.id ?? arg);
      await apiPost(`/panel/api/admins/resetUsage/${adminId}`);
      const updated = await apiGet(`/panel/api/admins/get/${adminId}`);
      return normalizeAdmin(updated ?? { id: adminId });
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['pg-ui', 'admins'] }),
  });
}

export function useCreateRole() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (arg: unknown) => {
      const input = asRecord(arg);
        const data = asRecord(input.data ?? arg);
      const created = await apiPost('/panel/api/admin-roles/add', pgRoleToPRIMEVPNPayload(data));
      return normalizeRole(created ?? data);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['pg-ui', 'roles'] });
      qc.invalidateQueries({ queryKey: ['pg-ui', 'roles-simple'] });
    },
  });
}

export function useModifyRole() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (arg: unknown) => {
      const input = asRecord(arg);
        const roleId = toNumber(input.roleId ?? input.id);
      const data = asRecord(input.data ?? input.payload ?? arg);
      const updated = await apiPost(`/panel/api/admin-roles/update/${roleId}`, pgRoleToPRIMEVPNPayload(data));
      return normalizeRole(updated ?? { ...data, id: roleId });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['pg-ui', 'roles'] });
      qc.invalidateQueries({ queryKey: ['pg-ui', 'roles-simple'] });
    },
  });
}

export function useDeleteRole() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (arg: unknown) => {
      const input = asRecord(arg);
        const roleId = toNumber(input.roleId ?? input.id ?? arg);
      await apiPost(`/panel/api/admin-roles/del/${roleId}`);
      return { id: roleId };
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['pg-ui', 'roles'] });
      qc.invalidateQueries({ queryKey: ['pg-ui', 'roles-simple'] });
    },
  });
}

export function useDuplicateRole() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (arg: unknown) => {
      const input = asRecord(arg);
        const roleId = toNumber(input.roleId ?? input.id ?? arg);
      const duplicated = await apiPost(`/panel/api/admin-roles/duplicate/${roleId}`);
      return normalizeRole(duplicated ?? { id: roleId });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['pg-ui', 'roles'] });
      qc.invalidateQueries({ queryKey: ['pg-ui', 'roles-simple'] });
    },
  });
}

// ---- Additional PasarGuard admin-page compatibility exports ----

export type AdminSimple = Pick<AdminDetails, 'id' | 'username' | 'status' | 'role'>;

export function useGetAdminsSimple(...args: unknown[]) {
  const queryOptions = extractQueryOptions(args);
  return useQuery({
    queryKey: ['pg-ui', 'admins-simple', ...args],
    queryFn: async () => {
      const admins = await fetchAdmins();
      return {
        admins,
        data: admins,
        items: admins,
        total: admins.length,
      };
    },
    ...(queryOptions as object),
  });
}

export function useGetGroupsSimple(...args: unknown[]) {
  const queryOptions = extractQueryOptions(args);
  return useQuery({
    queryKey: ['pg-ui', 'groups-simple', ...args],
    queryFn: async () => ({ groups: [], data: [], items: [], total: 0 }),
    ...(queryOptions as object),
  });
}

export function useGetCoresSimple(...args: unknown[]) {
  const queryOptions = extractQueryOptions(args);
  return useQuery({
    queryKey: ['pg-ui', 'cores-simple', ...args],
    queryFn: async () => ({ cores: [], data: [], items: [], total: 0 }),
    ...(queryOptions as object),
  });
}

type AdminActionResult = {
  count?: number;
  affected?: number;
  deleted?: number;
  failed?: number;
  success?: boolean;
};

function extractAdminIds(arg: unknown): number[] {
  const input = asRecord(arg);
  const data = asRecord(input.data);
  const raw = data.ids ?? input.ids ?? input.adminIds ?? [];
  const ids = Array.isArray(raw) ? raw : [];
  return ids.map(toNumber).filter(id => Number.isFinite(id) && id > 0);
}

function resultCount(result: AdminActionResult | undefined, fallback = 0): number {
  const count = toNumber(result?.count ?? result?.affected ?? result?.deleted);
  return count > 0 ? count : fallback;
}

function useRealAdminMutation<TArg = unknown, TResult = unknown>(mutationFn: (arg: TArg) => Promise<TResult>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['pg-ui', 'admins'] });
      qc.invalidateQueries({ queryKey: ['pg-ui', 'admins-simple'] });
    },
  });
}

async function runForAdminIds(ids: number[], action: (id: number) => Promise<AdminActionResult>): Promise<AdminActionResult> {
  let count = 0;
  let failed = 0;
  let firstError: unknown = null;

  for (const id of ids) {
    try {
      const result = await action(id);
      count += resultCount(result, 1);
    } catch (error) {
      failed += 1;
      if (!firstError) firstError = error;
    }
  }

  if (failed > 0 && count === 0) {
    throw firstError instanceof Error ? firstError : new Error('Admin action failed');
  }

  return { count, failed };
}

export function useBulkDeleteAdmins() {
  return useRealAdminMutation(async (arg: unknown) => {
    return runForAdminIds(extractAdminIds(arg), async id => {
      await apiPost(`/panel/api/admins/del/${id}`);
      return { count: 1 };
    });
  });
}

export function useBulkDisableAdmins() {
  return useRealAdminMutation(async (arg: unknown) => {
    return runForAdminIds(extractAdminIds(arg), async id => {
      await apiPost(`/panel/api/admins/disable/${id}`);
      return { count: 1 };
    });
  });
}

export function useBulkEnableAdmins() {
  return useRealAdminMutation(async (arg: unknown) => {
    return runForAdminIds(extractAdminIds(arg), async id => {
      await apiPost(`/panel/api/admins/enable/${id}`);
      return { count: 1 };
    });
  });
}

export function useBulkResetAdminsUsage() {
  return useRealAdminMutation(async (arg: unknown) => {
    return runForAdminIds(extractAdminIds(arg), async id => {
      await apiPost(`/panel/api/admins/resetUsage/${id}`);
      return { count: 1 };
    });
  });
}

export function useBulkActivateAllDisabledUsers() {
  return useRealAdminMutation(async (arg: unknown) => {
    return runForAdminIds(extractAdminIds(arg), async id => {
      const result = await apiPost<AdminActionResult>(`/panel/api/admins/users/activateDisabled/${id}`);
      return { count: resultCount(result, 0) };
    });
  });
}

export function useBulkDisableAllActiveUsers() {
  return useRealAdminMutation(async (arg: unknown) => {
    return runForAdminIds(extractAdminIds(arg), async id => {
      const result = await apiPost<AdminActionResult>(`/panel/api/admins/users/disableActive/${id}`);
      return { count: resultCount(result, 0) };
    });
  });
}

export function useBulkRemoveAllUsers() {
  return useRealAdminMutation(async (arg: unknown) => {
    return runForAdminIds(extractAdminIds(arg), async id => {
      const result = await apiPost<AdminActionResult>(`/panel/api/admins/users/removeAll/${id}`);
      return { count: resultCount(result, 0), deleted: resultCount(result, 0) };
    });
  });
}

export function useActivateAllDisabledUsersById() {
  return useRealAdminMutation(async (arg: unknown) => {
    const input = asRecord(arg);
        const adminId = toNumber(input.adminId ?? input.id ?? arg);
    const result = await apiPost<AdminActionResult>(`/panel/api/admins/users/activateDisabled/${adminId}`);
    return { ...result, count: resultCount(result, 0) };
  });
}

export function useDisableAllActiveUsersById() {
  return useRealAdminMutation(async (arg: unknown) => {
    const input = asRecord(arg);
        const adminId = toNumber(input.adminId ?? input.id ?? arg);
    const result = await apiPost<AdminActionResult>(`/panel/api/admins/users/disableActive/${adminId}`);
    return { ...result, count: resultCount(result, 0) };
  });
}

export function useRemoveAllUsersById() {
  return useRealAdminMutation(async (arg: unknown) => {
    const input = asRecord(arg);
        const adminId = toNumber(input.adminId ?? input.id ?? arg);
    const result = await apiPost<AdminActionResult>(`/panel/api/admins/users/removeAll/${adminId}`);
    return { ...result, count: resultCount(result, 0), deleted: resultCount(result, 0) };
  });
}
