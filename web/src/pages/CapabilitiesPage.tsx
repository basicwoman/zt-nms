import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus,
  Search,
  Key,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Shield,
  Server,
  MoreHorizontal,
  Ban,
  Eye,
  RefreshCw,
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from '@/components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Label } from '@/components/ui/label'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { capabilitiesApi, devicesApi, identitiesApi } from '@/api/client'
import type { CapabilityToken, CapabilityStatus } from '@/types/api'

const statusConfig: Record<CapabilityStatus, { icon: React.ElementType; color: string; bgColor: string; label: string }> = {
  active: { icon: CheckCircle, color: 'text-green-500', bgColor: 'bg-green-500/10', label: 'Active' },
  expired: { icon: Clock, color: 'text-gray-500', bgColor: 'bg-gray-500/10', label: 'Expired' },
  revoked: { icon: XCircle, color: 'text-red-500', bgColor: 'bg-red-500/10', label: 'Revoked' },
  pending_approval: { icon: AlertTriangle, color: 'text-yellow-500', bgColor: 'bg-yellow-500/10', label: 'Pending' },
}

export function CapabilitiesPage() {
  const queryClient = useQueryClient()
  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [isRequestDialogOpen, setIsRequestDialogOpen] = useState(false)
  const [selectedCapability, setSelectedCapability] = useState<CapabilityToken | null>(null)
  const [newRequest, setNewRequest] = useState({
    subjectId: '',
    deviceId: '',
    actions: [] as string[],
    duration: '1h',
    justification: '',
  })

  // For demo purposes, we'll use a mock subject ID
  const mockSubjectId = 'current-user-id'

  const { data: capabilitiesData, isLoading } = useQuery({
    queryKey: ['capabilities', mockSubjectId, statusFilter],
    queryFn: () =>
      capabilitiesApi.list({
        subject_id: mockSubjectId,
        active: statusFilter === 'active' ? true : undefined,
      }),
  })

  const { data: devicesData } = useQuery({
    queryKey: ['devices-simple'],
    queryFn: () => devicesApi.list({ limit: 100 }),
  })

  const requestMutation = useMutation({
    mutationFn: capabilitiesApi.request,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['capabilities'] })
      setIsRequestDialogOpen(false)
      setNewRequest({ subjectId: '', deviceId: '', actions: [], duration: '1h', justification: '' })
    },
  })

  const approveMutation = useMutation({
    mutationFn: ({ id, signature }: { id: string; signature: string }) =>
      capabilitiesApi.approve(id, { approver_signature: signature }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['capabilities'] })
    },
  })

  const revokeMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      capabilitiesApi.revoke(id, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['capabilities'] })
    },
  })

  const handleRequestCapability = () => {
    requestMutation.mutate({
      resources: [
        {
          device_id: newRequest.deviceId,
          actions: newRequest.actions,
        },
      ],
      validity_duration: newRequest.duration,
      justification: newRequest.justification,
    })
  }

  const capabilities = capabilitiesData?.capabilities || []
  const devices = devicesData?.devices || []

  // Calculate stats
  const stats = {
    total: capabilities.length,
    active: capabilities.filter((c) => c.status === 'active').length,
    pending: capabilities.filter((c) => c.status === 'pending_approval').length,
    expired: capabilities.filter((c) => c.status === 'expired').length,
    revoked: capabilities.filter((c) => c.status === 'revoked').length,
  }

  const availableActions = ['read', 'write', 'execute', 'configure', 'restart', 'update']

  const getTimeRemaining = (expiresAt: string): string => {
    const now = new Date()
    const expiry = new Date(expiresAt)
    const diff = expiry.getTime() - now.getTime()

    if (diff < 0) return 'Expired'

    const hours = Math.floor(diff / (1000 * 60 * 60))
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60))

    if (hours > 24) {
      const days = Math.floor(hours / 24)
      return `${days}d ${hours % 24}h`
    }
    if (hours > 0) {
      return `${hours}h ${minutes}m`
    }
    return `${minutes}m`
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Capabilities</h1>
          <p className="text-muted-foreground">Manage capability tokens and access grants</p>
        </div>
        <Dialog open={isRequestDialogOpen} onOpenChange={setIsRequestDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Request Capability
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Request New Capability</DialogTitle>
              <DialogDescription>
                Request access to perform specific actions on a device.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label>Target Device</Label>
                <Select
                  value={newRequest.deviceId}
                  onValueChange={(value) => setNewRequest({ ...newRequest, deviceId: value })}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select a device" />
                  </SelectTrigger>
                  <SelectContent>
                    {devices.map((device) => (
                      <SelectItem key={device.id} value={device.id}>
                        {device.hostname}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Actions</Label>
                <div className="flex flex-wrap gap-2">
                  {availableActions.map((action) => (
                    <Badge
                      key={action}
                      variant={newRequest.actions.includes(action) ? 'default' : 'outline'}
                      className="cursor-pointer"
                      onClick={() => {
                        if (newRequest.actions.includes(action)) {
                          setNewRequest({
                            ...newRequest,
                            actions: newRequest.actions.filter((a) => a !== action),
                          })
                        } else {
                          setNewRequest({
                            ...newRequest,
                            actions: [...newRequest.actions, action],
                          })
                        }
                      }}
                    >
                      {action}
                    </Badge>
                  ))}
                </div>
              </div>
              <div className="space-y-2">
                <Label>Duration</Label>
                <Select
                  value={newRequest.duration}
                  onValueChange={(value) => setNewRequest({ ...newRequest, duration: value })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1h">1 Hour</SelectItem>
                    <SelectItem value="4h">4 Hours</SelectItem>
                    <SelectItem value="8h">8 Hours</SelectItem>
                    <SelectItem value="24h">24 Hours</SelectItem>
                    <SelectItem value="7d">7 Days</SelectItem>
                    <SelectItem value="30d">30 Days</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Justification</Label>
                <textarea
                  value={newRequest.justification}
                  onChange={(e) => setNewRequest({ ...newRequest, justification: e.target.value })}
                  placeholder="Explain why you need this access..."
                  className="w-full h-24 p-3 rounded-md border bg-background text-sm"
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setIsRequestDialogOpen(false)}>
                Cancel
              </Button>
              <Button
                onClick={handleRequestCapability}
                disabled={requestMutation.isPending || !newRequest.deviceId || newRequest.actions.length === 0}
              >
                {requestMutation.isPending ? 'Requesting...' : 'Request'}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Key className="h-4 w-4" /> Total
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-green-500" /> Active
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{stats.active}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-yellow-500" /> Pending
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-yellow-600">{stats.pending}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Clock className="h-4 w-4 text-gray-500" /> Expired
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-gray-600">{stats.expired}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <XCircle className="h-4 w-4 text-red-500" /> Revoked
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{stats.revoked}</div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <Card>
        <CardHeader>
          <CardTitle>Capability Tokens</CardTitle>
          <CardDescription>View and manage access capability tokens</CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="active">
            <div className="flex items-center justify-between mb-4">
              <TabsList>
                <TabsTrigger value="active">Active</TabsTrigger>
                <TabsTrigger value="pending">Pending Approval</TabsTrigger>
                <TabsTrigger value="all">All Tokens</TabsTrigger>
              </TabsList>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search capabilities..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10 w-[200px]"
                />
              </div>
            </div>

            {isLoading ? (
              <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
              </div>
            ) : (
              <>
                <TabsContent value="active" className="mt-0">
                  <CapabilityTable
                    capabilities={capabilities.filter((c) => c.status === 'active')}
                    onRevoke={(id) => revokeMutation.mutate({ id, reason: 'Manual revocation' })}
                    getTimeRemaining={getTimeRemaining}
                  />
                </TabsContent>
                <TabsContent value="pending" className="mt-0">
                  <CapabilityTable
                    capabilities={capabilities.filter((c) => c.status === 'pending_approval')}
                    onApprove={(id) => approveMutation.mutate({ id, signature: 'mock-signature' })}
                    onRevoke={(id) => revokeMutation.mutate({ id, reason: 'Denied' })}
                    getTimeRemaining={getTimeRemaining}
                    showApprove
                  />
                </TabsContent>
                <TabsContent value="all" className="mt-0">
                  <CapabilityTable
                    capabilities={capabilities}
                    onRevoke={(id) => revokeMutation.mutate({ id, reason: 'Manual revocation' })}
                    getTimeRemaining={getTimeRemaining}
                  />
                </TabsContent>
              </>
            )}
          </Tabs>
        </CardContent>
      </Card>

      {/* Capability Detail Dialog */}
      {selectedCapability && (
        <Dialog open={!!selectedCapability} onOpenChange={() => setSelectedCapability(null)}>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Capability Details</DialogTitle>
            </DialogHeader>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-muted-foreground">ID</Label>
                  <p className="font-mono text-sm">{selectedCapability.id}</p>
                </div>
                <div>
                  <Label className="text-muted-foreground">Subject</Label>
                  <p>{selectedCapability.subject_name || selectedCapability.subject_id}</p>
                </div>
                <div>
                  <Label className="text-muted-foreground">Status</Label>
                  <Badge
                    variant="outline"
                    className={statusConfig[selectedCapability.status].bgColor}
                  >
                    {statusConfig[selectedCapability.status].label}
                  </Badge>
                </div>
                <div>
                  <Label className="text-muted-foreground">Uses</Label>
                  <p>
                    {selectedCapability.use_count}
                    {selectedCapability.validity.max_uses
                      ? ` / ${selectedCapability.validity.max_uses}`
                      : ' (unlimited)'}
                  </p>
                </div>
              </div>
              <div>
                <Label className="text-muted-foreground">Grants</Label>
                <div className="mt-2 space-y-2">
                  {selectedCapability.grants.map((grant, i) => (
                    <div key={i} className="p-3 rounded-lg bg-muted">
                      <div className="flex items-center gap-2 mb-2">
                        <Server className="h-4 w-4" />
                        <span className="font-medium">
                          {grant.resource.type}: {grant.resource.id}
                        </span>
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {grant.actions.map((action) => (
                          <Badge key={action} variant="secondary">
                            {action}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-muted-foreground">Issued At</Label>
                  <p>{new Date(selectedCapability.issued_at).toLocaleString()}</p>
                </div>
                <div>
                  <Label className="text-muted-foreground">Expires At</Label>
                  <p>{new Date(selectedCapability.expires_at).toLocaleString()}</p>
                </div>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      )}
    </div>
  )
}

function CapabilityTable({
  capabilities,
  onApprove,
  onRevoke,
  getTimeRemaining,
  showApprove = false,
}: {
  capabilities: CapabilityToken[]
  onApprove?: (id: string) => void
  onRevoke: (id: string) => void
  getTimeRemaining: (expiresAt: string) => string
  showApprove?: boolean
}) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Subject</TableHead>
          <TableHead>Resources</TableHead>
          <TableHead>Actions</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Time Remaining</TableHead>
          <TableHead>Uses</TableHead>
          <TableHead className="w-[50px]"></TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {capabilities.length === 0 ? (
          <TableRow>
            <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
              No capabilities found
            </TableCell>
          </TableRow>
        ) : (
          capabilities.map((cap) => {
            const statusInfo = statusConfig[cap.status]
            const StatusIcon = statusInfo.icon

            return (
              <TableRow key={cap.id}>
                <TableCell>
                  <div className="font-medium">{cap.subject_name || 'Unknown'}</div>
                  <div className="text-xs text-muted-foreground font-mono">
                    {cap.subject_id.slice(0, 8)}...
                  </div>
                </TableCell>
                <TableCell>
                  {cap.grants.map((grant, i) => (
                    <div key={i} className="flex items-center gap-1">
                      <Server className="h-3 w-3" />
                      <span className="text-sm">{grant.resource.id.slice(0, 8)}...</span>
                    </div>
                  ))}
                </TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-1 max-w-[200px]">
                    {cap.grants.flatMap((g) => g.actions).slice(0, 3).map((action) => (
                      <Badge key={action} variant="secondary" className="text-xs">
                        {action}
                      </Badge>
                    ))}
                    {cap.grants.flatMap((g) => g.actions).length > 3 && (
                      <Badge variant="secondary" className="text-xs">
                        +{cap.grants.flatMap((g) => g.actions).length - 3}
                      </Badge>
                    )}
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <StatusIcon className={`h-4 w-4 ${statusInfo.color}`} />
                    <span>{statusInfo.label}</span>
                  </div>
                </TableCell>
                <TableCell>
                  {cap.status === 'active' ? (
                    <span className={getTimeRemaining(cap.expires_at) === 'Expired' ? 'text-red-500' : ''}>
                      {getTimeRemaining(cap.expires_at)}
                    </span>
                  ) : (
                    '-'
                  )}
                </TableCell>
                <TableCell>
                  {cap.use_count}
                  {cap.validity.max_uses ? ` / ${cap.validity.max_uses}` : ''}
                </TableCell>
                <TableCell>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="icon">
                        <MoreHorizontal className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem>
                        <Eye className="mr-2 h-4 w-4" />
                        View Details
                      </DropdownMenuItem>
                      {showApprove && onApprove && (
                        <DropdownMenuItem onClick={() => onApprove(cap.id)} className="text-green-600">
                          <CheckCircle className="mr-2 h-4 w-4" />
                          Approve
                        </DropdownMenuItem>
                      )}
                      {cap.validity.renewable && cap.status === 'active' && (
                        <DropdownMenuItem>
                          <RefreshCw className="mr-2 h-4 w-4" />
                          Renew
                        </DropdownMenuItem>
                      )}
                      <DropdownMenuSeparator />
                      {(cap.status === 'active' || cap.status === 'pending_approval') && (
                        <DropdownMenuItem
                          onClick={() => onRevoke(cap.id)}
                          className="text-red-600"
                        >
                          <Ban className="mr-2 h-4 w-4" />
                          {cap.status === 'pending_approval' ? 'Deny' : 'Revoke'}
                        </DropdownMenuItem>
                      )}
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TableCell>
              </TableRow>
            )
          })
        )}
      </TableBody>
    </Table>
  )
}
