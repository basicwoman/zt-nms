import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Plus,
  Search,
  Filter,
  MoreHorizontal,
  User,
  Server,
  Cpu,
  Shield,
  Ban,
  CheckCircle,
  Clock,
  XCircle,
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
import { identitiesApi } from '@/api/client'
import type { Identity, IdentityType, IdentityStatus } from '@/types/api'

const statusConfig: Record<IdentityStatus, { icon: React.ElementType; color: string; label: string }> = {
  active: { icon: CheckCircle, color: 'text-green-500', label: 'Active' },
  suspended: { icon: Ban, color: 'text-yellow-500', label: 'Suspended' },
  revoked: { icon: XCircle, color: 'text-red-500', label: 'Revoked' },
  pending: { icon: Clock, color: 'text-blue-500', label: 'Pending' },
}

const typeIcons: Record<IdentityType, React.ElementType> = {
  operator: User,
  device: Server,
  service: Cpu,
}

export function IdentitiesPage() {
  const queryClient = useQueryClient()
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)
  const [newIdentity, setNewIdentity] = useState({
    type: 'operator' as IdentityType,
    username: '',
    email: '',
    publicKey: '',
  })

  const { data, isLoading, error } = useQuery({
    queryKey: ['identities', searchQuery, typeFilter, statusFilter],
    queryFn: () =>
      identitiesApi.list({
        search: searchQuery || undefined,
        type: typeFilter !== 'all' ? typeFilter : undefined,
        status: statusFilter !== 'all' ? statusFilter : undefined,
        limit: 100,
      }),
  })

  const createMutation = useMutation({
    mutationFn: (data: { type: string; attributes: Record<string, unknown>; public_key: string }) =>
      identitiesApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identities'] })
      setIsCreateDialogOpen(false)
      setNewIdentity({ type: 'operator', username: '', email: '', publicKey: '' })
    },
  })

  const suspendMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      identitiesApi.suspend(id, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identities'] })
    },
  })

  const activateMutation = useMutation({
    mutationFn: (id: string) => identitiesApi.activate(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identities'] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => identitiesApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identities'] })
    },
  })

  const handleCreateIdentity = () => {
    const attributes: Record<string, unknown> =
      newIdentity.type === 'operator'
        ? { username: newIdentity.username, email: newIdentity.email, groups: [], certifications: [], clearance_level: 1 }
        : newIdentity.type === 'device'
        ? { hostname: newIdentity.username, vendor: '', model: '', serial: '', location: '', role: 'router', criticality: 'medium' }
        : { name: newIdentity.username, owner: '', purpose: '', allowed_operations: [] }

    createMutation.mutate({
      type: newIdentity.type,
      attributes,
      public_key: newIdentity.publicKey,
    })
  }

  const getIdentityName = (identity: Identity): string => {
    const attrs = identity.attributes
    if ('username' in attrs) return attrs.username as string
    if ('hostname' in attrs) return attrs.hostname as string
    if ('name' in attrs) return attrs.name as string
    return identity.id
  }

  const getIdentityEmail = (identity: Identity): string | undefined => {
    const attrs = identity.attributes
    if ('email' in attrs) return attrs.email as string
    return undefined
  }

  const identities = data?.identities || []

  // Calculate stats
  const stats = {
    total: identities.length,
    operators: identities.filter((i) => i.type === 'operator').length,
    devices: identities.filter((i) => i.type === 'device').length,
    services: identities.filter((i) => i.type === 'service').length,
    active: identities.filter((i) => i.status === 'active').length,
    suspended: identities.filter((i) => i.status === 'suspended').length,
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <XCircle className="h-12 w-12 text-red-500 mx-auto mb-4" />
          <h2 className="text-xl font-semibold mb-2">Error Loading Identities</h2>
          <p className="text-muted-foreground">Please try again later</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Identities</h1>
          <p className="text-muted-foreground">Manage operators, devices, and service identities</p>
        </div>
        <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Create Identity
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create New Identity</DialogTitle>
              <DialogDescription>
                Add a new operator, device, or service identity to the system.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label>Type</Label>
                <Select
                  value={newIdentity.type}
                  onValueChange={(value) => setNewIdentity({ ...newIdentity, type: value as IdentityType })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="operator">Operator</SelectItem>
                    <SelectItem value="device">Device</SelectItem>
                    <SelectItem value="service">Service</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>
                  {newIdentity.type === 'operator' ? 'Username' : newIdentity.type === 'device' ? 'Hostname' : 'Name'}
                </Label>
                <Input
                  value={newIdentity.username}
                  onChange={(e) => setNewIdentity({ ...newIdentity, username: e.target.value })}
                  placeholder={newIdentity.type === 'operator' ? 'john.doe' : newIdentity.type === 'device' ? 'router-01' : 'my-service'}
                />
              </div>
              {newIdentity.type === 'operator' && (
                <div className="space-y-2">
                  <Label>Email</Label>
                  <Input
                    type="email"
                    value={newIdentity.email}
                    onChange={(e) => setNewIdentity({ ...newIdentity, email: e.target.value })}
                    placeholder="john.doe@company.com"
                  />
                </div>
              )}
              <div className="space-y-2">
                <Label>Public Key (Ed25519, Base64)</Label>
                <Input
                  value={newIdentity.publicKey}
                  onChange={(e) => setNewIdentity({ ...newIdentity, publicKey: e.target.value })}
                  placeholder="Base64 encoded public key"
                  className="font-mono text-sm"
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setIsCreateDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleCreateIdentity} disabled={createMutation.isPending}>
                {createMutation.isPending ? 'Creating...' : 'Create'}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-6">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <User className="h-4 w-4" /> Operators
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.operators}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Server className="h-4 w-4" /> Devices
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.devices}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Cpu className="h-4 w-4" /> Services
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.services}</div>
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
              <Ban className="h-4 w-4 text-yellow-500" /> Suspended
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-yellow-600">{stats.suspended}</div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle>Identity Management</CardTitle>
          <CardDescription>View and manage all system identities</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-4 mb-6">
            <div className="flex-1 min-w-[200px]">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search identities..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            <Select value={typeFilter} onValueChange={setTypeFilter}>
              <SelectTrigger className="w-[150px]">
                <Filter className="mr-2 h-4 w-4" />
                <SelectValue placeholder="Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="operator">Operators</SelectItem>
                <SelectItem value="device">Devices</SelectItem>
                <SelectItem value="service">Services</SelectItem>
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[150px]">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="suspended">Suspended</SelectItem>
                <SelectItem value="revoked">Revoked</SelectItem>
                <SelectItem value="pending">Pending</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center h-64">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Identity</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Last Auth</TableHead>
                  <TableHead className="w-[50px]"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {identities.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                      No identities found
                    </TableCell>
                  </TableRow>
                ) : (
                  identities.map((identity) => {
                    const TypeIcon = typeIcons[identity.type]
                    const statusInfo = statusConfig[identity.status]
                    const StatusIcon = statusInfo.icon

                    return (
                      <TableRow key={identity.id}>
                        <TableCell>
                          <Link
                            to={`/identities/${identity.id}`}
                            className="flex items-center gap-3 hover:underline"
                          >
                            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-muted">
                              <TypeIcon className="h-5 w-5" />
                            </div>
                            <div>
                              <div className="font-medium">{getIdentityName(identity)}</div>
                              <div className="text-sm text-muted-foreground">
                                {getIdentityEmail(identity) || identity.id.slice(0, 8)}
                              </div>
                            </div>
                          </Link>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="capitalize">
                            {identity.type}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <StatusIcon className={`h-4 w-4 ${statusInfo.color}`} />
                            <span>{statusInfo.label}</span>
                          </div>
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          {new Date(identity.created_at).toLocaleDateString()}
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          {identity.last_auth
                            ? new Date(identity.last_auth).toLocaleString()
                            : 'Never'}
                        </TableCell>
                        <TableCell>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="icon">
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem asChild>
                                <Link to={`/identities/${identity.id}`}>View Details</Link>
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              {identity.status === 'active' ? (
                                <DropdownMenuItem
                                  onClick={() =>
                                    suspendMutation.mutate({
                                      id: identity.id,
                                      reason: 'Suspended by administrator',
                                    })
                                  }
                                  className="text-yellow-600"
                                >
                                  <Ban className="mr-2 h-4 w-4" />
                                  Suspend
                                </DropdownMenuItem>
                              ) : identity.status === 'suspended' ? (
                                <DropdownMenuItem
                                  onClick={() => activateMutation.mutate(identity.id)}
                                  className="text-green-600"
                                >
                                  <CheckCircle className="mr-2 h-4 w-4" />
                                  Activate
                                </DropdownMenuItem>
                              ) : null}
                              <DropdownMenuItem
                                onClick={() => {
                                  if (confirm('Are you sure you want to delete this identity?')) {
                                    deleteMutation.mutate(identity.id)
                                  }
                                }}
                                className="text-red-600"
                              >
                                <XCircle className="mr-2 h-4 w-4" />
                                Delete
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    )
                  })
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
