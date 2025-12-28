import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  dashboardApi,
  devicesApi,
  identitiesApi,
  policiesApi,
  capabilitiesApi,
  auditApi,
} from '@/api/client'

// Dashboard hooks
export function useDashboardStats() {
  return useQuery({
    queryKey: ['dashboard', 'stats'],
    queryFn: dashboardApi.getStats,
    staleTime: 30 * 1000, // 30 seconds
    refetchInterval: 60 * 1000, // 1 minute
  })
}

// Devices hooks
export function useDevices(params?: Parameters<typeof devicesApi.list>[0]) {
  return useQuery({
    queryKey: ['devices', params],
    queryFn: () => devicesApi.list(params),
  })
}

export function useDevice(id: string) {
  return useQuery({
    queryKey: ['devices', id],
    queryFn: () => devicesApi.get(id),
    enabled: !!id,
  })
}

export function useDeviceConfig(id: string, params?: Parameters<typeof devicesApi.getConfig>[1]) {
  return useQuery({
    queryKey: ['devices', id, 'config', params],
    queryFn: () => devicesApi.getConfig(id, params),
    enabled: !!id,
  })
}

export function useDeviceConfigHistory(id: string, params?: Parameters<typeof devicesApi.getConfigHistory>[1]) {
  return useQuery({
    queryKey: ['devices', id, 'config-history', params],
    queryFn: () => devicesApi.getConfigHistory(id, params),
    enabled: !!id,
  })
}

export function useDeviceAttestation(id: string) {
  return useQuery({
    queryKey: ['devices', id, 'attestation'],
    queryFn: () => devicesApi.getAttestation(id),
    enabled: !!id,
  })
}

export function useRegisterDevice() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: devicesApi.register,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] })
    },
  })
}

export function useUpdateDevice() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Parameters<typeof devicesApi.update>[1] }) =>
      devicesApi.update(id, data),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: ['devices'] })
      queryClient.invalidateQueries({ queryKey: ['devices', id] })
    },
  })
}

export function useDeleteDevice() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: devicesApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] })
    },
  })
}

export function useExecuteDeviceOperation() {
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Parameters<typeof devicesApi.executeOperation>[1] }) =>
      devicesApi.executeOperation(id, data),
  })
}

// Identities hooks
export function useIdentities(params?: Parameters<typeof identitiesApi.list>[0]) {
  return useQuery({
    queryKey: ['identities', params],
    queryFn: () => identitiesApi.list(params),
  })
}

export function useIdentity(id: string) {
  return useQuery({
    queryKey: ['identities', id],
    queryFn: () => identitiesApi.get(id),
    enabled: !!id,
  })
}

export function useCreateIdentity() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: identitiesApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identities'] })
    },
  })
}

export function useUpdateIdentity() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Parameters<typeof identitiesApi.update>[1] }) =>
      identitiesApi.update(id, data),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: ['identities'] })
      queryClient.invalidateQueries({ queryKey: ['identities', id] })
    },
  })
}

export function useDeleteIdentity() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: identitiesApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identities'] })
    },
  })
}

export function useSuspendIdentity() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      identitiesApi.suspend(id, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identities'] })
    },
  })
}

export function useActivateIdentity() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: identitiesApi.activate,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identities'] })
    },
  })
}

// Policies hooks
export function usePolicies(params?: Parameters<typeof policiesApi.list>[0]) {
  return useQuery({
    queryKey: ['policies', params],
    queryFn: () => policiesApi.list(params),
  })
}

export function usePolicy(id: string) {
  return useQuery({
    queryKey: ['policies', id],
    queryFn: () => policiesApi.get(id),
    enabled: !!id,
  })
}

export function useCreatePolicy() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: policiesApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
    },
  })
}

export function useUpdatePolicy() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Parameters<typeof policiesApi.update>[1] }) =>
      policiesApi.update(id, data),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      queryClient.invalidateQueries({ queryKey: ['policies', id] })
    },
  })
}

export function useDeletePolicy() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: policiesApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
    },
  })
}

export function useActivatePolicy() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: policiesApi.activate,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
    },
  })
}

export function useEvaluatePolicy() {
  return useMutation({
    mutationFn: policiesApi.evaluate,
  })
}

// Capabilities hooks
export function useCapabilities(params: Parameters<typeof capabilitiesApi.list>[0]) {
  return useQuery({
    queryKey: ['capabilities', params],
    queryFn: () => capabilitiesApi.list(params),
  })
}

export function useCapability(id: string) {
  return useQuery({
    queryKey: ['capabilities', id],
    queryFn: () => capabilitiesApi.get(id),
    enabled: !!id,
  })
}

export function useRequestCapability() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: capabilitiesApi.request,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['capabilities'] })
    },
  })
}

export function useApproveCapability() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, signature }: { id: string; signature: string }) =>
      capabilitiesApi.approve(id, { approver_signature: signature }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['capabilities'] })
    },
  })
}

export function useRevokeCapability() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      capabilitiesApi.revoke(id, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['capabilities'] })
    },
  })
}

// Audit hooks
export function useAuditEvents(params?: Parameters<typeof auditApi.list>[0]) {
  return useQuery({
    queryKey: ['audit', 'events', params],
    queryFn: () => auditApi.list(params),
  })
}

export function useAuditEvent(id: string) {
  return useQuery({
    queryKey: ['audit', 'events', id],
    queryFn: () => auditApi.get(id),
    enabled: !!id,
  })
}

export function useVerifyAuditEvent() {
  return useMutation({
    mutationFn: auditApi.verify,
  })
}
