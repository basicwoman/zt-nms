import { useState } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft,
  User,
  Server,
  Cpu,
  Shield,
  Key,
  Clock,
  CheckCircle,
  XCircle,
  Ban,
  Activity,
  FileText,
  MoreHorizontal,
  Trash2,
  Edit,
  Copy,
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
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
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { identitiesApi } from '@/api/client'
import type { Identity, IdentityType, IdentityStatus, CapabilityToken, AuditEvent } from '@/types/api'

const statusConfig: Record<IdentityStatus, { icon: React.ElementType; color: string; bgColor: string; label: string }> = {
  active: { icon: CheckCircle, color: 'text-green-500', bgColor: 'bg-green-500/10', label: 'Active' },
  suspended: { icon: Ban, color: 'text-yellow-500', bgColor: 'bg-yellow-500/10', label: 'Suspended' },
  revoked: { icon: XCircle, color: 'text-red-500', bgColor: 'bg-red-500/10', label: 'Revoked' },
  pending: { icon: Clock, color: 'text-blue-500', bgColor: 'bg-blue-500/10', label: 'Pending' },
}

const typeIcons: Record<IdentityType, React.ElementType> = {
  operator: User,
  device: Server,
  service: Cpu,
}

// Mock data
const mockIdentity: Identity = {
  id: 'id-001',
  type: 'operator',
  attributes: {
    username: 'john.doe',
    email: 'john.doe@company.com',
    groups: ['network-admins', 'security-team'],
    certifications: ['CCNP', 'CCIE'],
    clearance_level: 3,
  },
  public_key: 'ed25519:MCowBQYDK2VwAyEA1234567890abcdefghijklmnopqrstuvwxyz...',
  certificate: 'MIIBkTCB+wIJALr...',
  status: 'active',
  created_at: new Date(Date.now() - 30 * 86400000).toISOString(),
  updated_at: new Date(Date.now() - 86400000).toISOString(),
  created_by: 'admin',
  last_auth: new Date(Date.now() - 3600000).toISOString(),
}

const mockCapabilities: CapabilityToken[] = [
  {
    id: 'cap-001',
    subject_id: 'id-001',
    subject_name: 'john.doe',
    grants: [
      {
        resource: { type: 'device', id: 'dev-*', pattern: 'dev-*' },
        actions: ['read', 'configure'],
      },
    ],
    validity: { not_before: new Date().toISOString(), not_after: new Date(Date.now() + 86400000).toISOString() },
    status: 'active',
    use_count: 15,
    issued_at: new Date(Date.now() - 3600000).toISOString(),
    expires_at: new Date(Date.now() + 86400000).toISOString(),
  },
  {
    id: 'cap-002',
    subject_id: 'id-001',
    subject_name: 'john.doe',
    grants: [
      {
        resource: { type: 'policy', id: 'pol-001' },
        actions: ['read'],
      },
    ],
    validity: { not_before: new Date().toISOString(), not_after: new Date(Date.now() + 3600000).toISOString() },
    status: 'active',
    use_count: 3,
    issued_at: new Date(Date.now() - 7200000).toISOString(),
    expires_at: new Date(Date.now() + 3600000).toISOString(),
  },
]

const mockAuditEvents: AuditEvent[] = [
  {
    id: 'evt-001',
    sequence: 1001,
    prev_hash: 'abc',
    event_hash: 'def',
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    event_type: 'auth',
    actor_id: 'id-001',
    actor_name: 'john.doe',
    actor_type: 'operator',
    resource_type: 'session',
    resource_id: 'sess-001',
    action: 'login',
    result: 'success',
    source_ip: '192.168.1.100',
  },
  {
    id: 'evt-002',
    sequence: 1002,
    prev_hash: 'def',
    event_hash: 'ghi',
    timestamp: new Date(Date.now() - 7200000).toISOString(),
    event_type: 'config',
    actor_id: 'id-001',
    actor_name: 'john.doe',
    actor_type: 'operator',
    resource_type: 'device',
    resource_id: 'router-01',
    action: 'deploy',
    result: 'success',
    source_ip: '192.168.1.100',
  },
]

export function IdentityDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [isSuspendDialogOpen, setIsSuspendDialogOpen] = useState(false)
  const [suspendReason, setSuspendReason] = useState('')

  // Using mock data
  const identity = mockIdentity
  const capabilities = mockCapabilities
  const auditEvents = mockAuditEvents

  const suspendMutation = useMutation({
    mutationFn: (reason: string) => identitiesApi.suspend(id!, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identities'] })
      setIsSuspendDialogOpen(false)
    },
  })

  const activateMutation = useMutation({
    mutationFn: () => identitiesApi.activate(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identities'] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: () => identitiesApi.delete(id!),
    onSuccess: () => {
      navigate('/identities')
    },
  })

  const TypeIcon = typeIcons[identity.type]
  const statusInfo = statusConfig[identity.status]
  const StatusIcon = statusInfo.icon

  const getIdentityName = (): string => {
    const attrs = identity.attributes as unknown as Record<string, unknown>
    return (attrs.username || attrs.hostname || attrs.name || identity.id) as string
  }

  const getIdentityEmail = (): string | undefined => {
    const attrs = identity.attributes as unknown as Record<string, unknown>
    return attrs.email as string | undefined
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" asChild>
            <Link to="/identities">
              <ArrowLeft className="h-4 w-4" />
            </Link>
          </Button>
          <div className="flex h-16 w-16 items-center justify-center rounded-full bg-muted">
            <TypeIcon className="h-8 w-8" />
          </div>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-3xl font-bold">{getIdentityName()}</h1>
              <Badge variant="outline" className="capitalize">{identity.type}</Badge>
            </div>
            <p className="text-muted-foreground mt-1">
              {getIdentityEmail() || identity.id}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {identity.status === 'active' ? (
            <Button variant="outline" onClick={() => setIsSuspendDialogOpen(true)}>
              <Ban className="mr-2 h-4 w-4" />
              Suspend
            </Button>
          ) : identity.status === 'suspended' ? (
            <Button variant="outline" onClick={() => activateMutation.mutate()}>
              <CheckCircle className="mr-2 h-4 w-4" />
              Activate
            </Button>
          ) : null}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="icon">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem>
                <Edit className="mr-2 h-4 w-4" />
                Edit Identity
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => copyToClipboard(identity.public_key)}>
                <Copy className="mr-2 h-4 w-4" />
                Copy Public Key
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={() => {
                  if (confirm('Are you sure you want to delete this identity?')) {
                    deleteMutation.mutate()
                  }
                }}
                className="text-red-600"
              >
                <Trash2 className="mr-2 h-4 w-4" />
                Delete Identity
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* Status Banner */}
      <Card className={`${statusInfo.bgColor}`}>
        <CardContent className="flex items-center gap-4 pt-6">
          <StatusIcon className={`h-8 w-8 ${statusInfo.color}`} />
          <div>
            <h3 className="font-semibold">Status: {statusInfo.label}</h3>
            <p className="text-sm text-muted-foreground">
              Created: {new Date(identity.created_at).toLocaleDateString()}
              {identity.last_auth && ` | Last auth: ${new Date(identity.last_auth).toLocaleString()}`}
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Info Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Type</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <TypeIcon className="h-5 w-5" />
              <span className="text-xl font-bold capitalize">{identity.type}</span>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Active Capabilities</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{capabilities.filter(c => c.status === 'active').length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Last Authentication</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-lg font-bold">
              {identity.last_auth ? new Date(identity.last_auth).toLocaleTimeString() : 'Never'}
            </div>
            <p className="text-xs text-muted-foreground">
              {identity.last_auth && new Date(identity.last_auth).toLocaleDateString()}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Account Age</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xl font-bold">
              {Math.floor((Date.now() - new Date(identity.created_at).getTime()) / 86400000)} days
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="capabilities">Capabilities</TabsTrigger>
          <TabsTrigger value="activity">Activity</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Identity Attributes</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {Object.entries(identity.attributes).map(([key, value]) => (
                  <div key={key} className="flex justify-between">
                    <span className="text-muted-foreground capitalize">{key.replace(/_/g, ' ')}</span>
                    <span className="font-medium">
                      {Array.isArray(value) ? (
                        <div className="flex flex-wrap gap-1 justify-end">
                          {value.map((v, i) => (
                            <Badge key={i} variant="secondary">{v}</Badge>
                          ))}
                        </div>
                      ) : (
                        String(value)
                      )}
                    </span>
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Cryptographic Identity</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label className="text-muted-foreground">Public Key</Label>
                  <div className="flex items-center gap-2 mt-1">
                    <code className="flex-1 p-2 rounded bg-muted font-mono text-xs break-all">
                      {identity.public_key}
                    </code>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => copyToClipboard(identity.public_key)}
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
                {identity.certificate && (
                  <div>
                    <Label className="text-muted-foreground">Certificate</Label>
                    <code className="block p-2 rounded bg-muted font-mono text-xs break-all mt-1">
                      {identity.certificate.slice(0, 64)}...
                    </code>
                  </div>
                )}
                <div>
                  <Label className="text-muted-foreground">Identity ID</Label>
                  <code className="block p-2 rounded bg-muted font-mono text-xs mt-1">
                    {identity.id}
                  </code>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="capabilities" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Active Capabilities</CardTitle>
              <CardDescription>Capability tokens assigned to this identity</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>ID</TableHead>
                    <TableHead>Resources</TableHead>
                    <TableHead>Actions</TableHead>
                    <TableHead>Expires</TableHead>
                    <TableHead>Uses</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {capabilities.map((cap) => (
                    <TableRow key={cap.id}>
                      <TableCell className="font-mono text-sm">{cap.id}</TableCell>
                      <TableCell>
                        {cap.grants.map((g, i) => (
                          <div key={i} className="text-sm">
                            {g.resource.type}: {g.resource.id}
                          </div>
                        ))}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {cap.grants.flatMap((g) => g.actions).map((action) => (
                            <Badge key={action} variant="secondary" className="text-xs">
                              {action}
                            </Badge>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell>{new Date(cap.expires_at).toLocaleString()}</TableCell>
                      <TableCell>{cap.use_count}</TableCell>
                      <TableCell>
                        <Badge variant={cap.status === 'active' ? 'default' : 'secondary'}>
                          {cap.status}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="activity" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Recent Activity</CardTitle>
              <CardDescription>Audit log of actions performed by this identity</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {auditEvents.map((event) => (
                  <div key={event.id} className="flex items-start gap-4 p-4 rounded-lg border">
                    <div className={`p-2 rounded-full ${event.result === 'success' ? 'bg-green-500/10' : 'bg-red-500/10'}`}>
                      {event.result === 'success' ? (
                        <CheckCircle className="h-4 w-4 text-green-500" />
                      ) : (
                        <XCircle className="h-4 w-4 text-red-500" />
                      )}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-medium capitalize">{event.action.replace(/_/g, ' ')}</span>
                        <Badge variant="outline">{event.event_type}</Badge>
                      </div>
                      <p className="text-sm text-muted-foreground mt-1">
                        {event.resource_type}: {event.resource_id}
                      </p>
                      <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                        <span>{new Date(event.timestamp).toLocaleString()}</span>
                        <span>IP: {event.source_ip}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="security" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Security Settings</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="font-medium">Multi-Factor Authentication</div>
                    <div className="text-sm text-muted-foreground">Require MFA for sensitive operations</div>
                  </div>
                  <Badge variant="default">Enabled</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <div className="font-medium">Session Timeout</div>
                    <div className="text-sm text-muted-foreground">Auto-logout after inactivity</div>
                  </div>
                  <span className="font-medium">30 minutes</span>
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <div className="font-medium">IP Restrictions</div>
                    <div className="text-sm text-muted-foreground">Limit access to specific networks</div>
                  </div>
                  <Badge variant="secondary">Not configured</Badge>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Recent Security Events</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="flex items-center gap-3 p-3 rounded-lg bg-green-500/10">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <div className="flex-1">
                      <div className="text-sm font-medium">Successful login</div>
                      <div className="text-xs text-muted-foreground">1 hour ago from 192.168.1.100</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 p-3 rounded-lg bg-green-500/10">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <div className="flex-1">
                      <div className="text-sm font-medium">MFA verification passed</div>
                      <div className="text-xs text-muted-foreground">1 hour ago</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 p-3 rounded-lg bg-yellow-500/10">
                    <Ban className="h-4 w-4 text-yellow-500" />
                    <div className="flex-1">
                      <div className="text-sm font-medium">Failed login attempt</div>
                      <div className="text-xs text-muted-foreground">2 days ago from 10.0.0.50</div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>

      {/* Suspend Dialog */}
      <Dialog open={isSuspendDialogOpen} onOpenChange={setIsSuspendDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Suspend Identity</DialogTitle>
            <DialogDescription>
              Suspending this identity will revoke all active capabilities and prevent authentication.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Label>Reason for suspension</Label>
            <Input
              value={suspendReason}
              onChange={(e) => setSuspendReason(e.target.value)}
              placeholder="Enter reason..."
              className="mt-2"
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsSuspendDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => suspendMutation.mutate(suspendReason)}
              disabled={suspendMutation.isPending || !suspendReason}
            >
              {suspendMutation.isPending ? 'Suspending...' : 'Suspend Identity'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
