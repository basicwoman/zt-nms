import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Plus,
  Search,
  Filter,
  MoreHorizontal,
  Shield,
  ShieldCheck,
  ShieldOff,
  FileText,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Copy,
  Play,
  Pause,
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
import { policiesApi } from '@/api/client'
import type { Policy, PolicyType, PolicyStatus } from '@/types/api'

const statusConfig: Record<PolicyStatus, { color: string; label: string }> = {
  draft: { color: 'bg-gray-500', label: 'Draft' },
  active: { color: 'bg-green-500', label: 'Active' },
  deprecated: { color: 'bg-yellow-500', label: 'Deprecated' },
  archived: { color: 'bg-red-500', label: 'Archived' },
}

const typeIcons: Record<PolicyType, React.ElementType> = {
  access: Shield,
  config: FileText,
  deployment: Clock,
  security: ShieldCheck,
  network: Shield,
}

export function PoliciesPage() {
  const queryClient = useQueryClient()
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)
  const [newPolicy, setNewPolicy] = useState({
    name: '',
    description: '',
    type: 'access' as PolicyType,
    rules: '[]',
  })

  const { data, isLoading, error } = useQuery({
    queryKey: ['policies', searchQuery, typeFilter, statusFilter],
    queryFn: () =>
      policiesApi.list({
        type: typeFilter !== 'all' ? typeFilter : undefined,
        status: statusFilter !== 'all' ? statusFilter : undefined,
        limit: 100,
      }),
  })

  const createMutation = useMutation({
    mutationFn: (data: Omit<Policy, 'id' | 'version' | 'created_at' | 'status' | 'approved_by' | 'approval_signature' | 'effective_from' | 'effective_until'>) =>
      policiesApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      setIsCreateDialogOpen(false)
      setNewPolicy({ name: '', description: '', type: 'access', rules: '[]' })
    },
  })

  const activateMutation = useMutation({
    mutationFn: (id: string) => policiesApi.activate(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => policiesApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
    },
  })

  const handleCreatePolicy = () => {
    try {
      const rules = JSON.parse(newPolicy.rules)
      createMutation.mutate({
        name: newPolicy.name,
        description: newPolicy.description,
        type: newPolicy.type,
        definition: { rules },
        created_by: 'current-user',
      })
    } catch {
      alert('Invalid JSON in rules')
    }
  }

  const policies = data?.policies || []

  // Calculate stats
  const stats = {
    total: policies.length,
    active: policies.filter((p) => p.status === 'active').length,
    draft: policies.filter((p) => p.status === 'draft').length,
    access: policies.filter((p) => p.type === 'access').length,
    config: policies.filter((p) => p.type === 'config').length,
    security: policies.filter((p) => p.type === 'security').length,
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <XCircle className="h-12 w-12 text-red-500 mx-auto mb-4" />
          <h2 className="text-xl font-semibold mb-2">Error Loading Policies</h2>
          <p className="text-muted-foreground">Please try again later</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Policies</h1>
          <p className="text-muted-foreground">Manage access control and security policies</p>
        </div>
        <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Create Policy
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Create New Policy</DialogTitle>
              <DialogDescription>
                Define a new policy for access control, configuration, or security.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Name</Label>
                  <Input
                    value={newPolicy.name}
                    onChange={(e) => setNewPolicy({ ...newPolicy, name: e.target.value })}
                    placeholder="policy-name"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Type</Label>
                  <Select
                    value={newPolicy.type}
                    onValueChange={(value) => setNewPolicy({ ...newPolicy, type: value as PolicyType })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="access">Access Control</SelectItem>
                      <SelectItem value="config">Configuration</SelectItem>
                      <SelectItem value="deployment">Deployment</SelectItem>
                      <SelectItem value="security">Security</SelectItem>
                      <SelectItem value="network">Network</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="space-y-2">
                <Label>Description</Label>
                <Input
                  value={newPolicy.description}
                  onChange={(e) => setNewPolicy({ ...newPolicy, description: e.target.value })}
                  placeholder="Policy description..."
                />
              </div>
              <div className="space-y-2">
                <Label>Rules (JSON)</Label>
                <textarea
                  value={newPolicy.rules}
                  onChange={(e) => setNewPolicy({ ...newPolicy, rules: e.target.value })}
                  placeholder='[{"name": "rule-1", "effect": "allow", ...}]'
                  className="w-full h-48 p-3 rounded-md border bg-background font-mono text-sm"
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setIsCreateDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleCreatePolicy} disabled={createMutation.isPending}>
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
            <CardTitle className="text-sm font-medium">Total Policies</CardTitle>
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
              <FileText className="h-4 w-4" /> Drafts
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.draft}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Shield className="h-4 w-4" /> Access
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.access}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <FileText className="h-4 w-4" /> Config
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.config}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <ShieldCheck className="h-4 w-4" /> Security
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.security}</div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <Card>
        <CardHeader>
          <CardTitle>Policy Management</CardTitle>
          <CardDescription>View and manage all system policies</CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="all">
            <div className="flex items-center justify-between mb-4">
              <TabsList>
                <TabsTrigger value="all">All Policies</TabsTrigger>
                <TabsTrigger value="access">Access</TabsTrigger>
                <TabsTrigger value="config">Config</TabsTrigger>
                <TabsTrigger value="security">Security</TabsTrigger>
              </TabsList>
              <div className="flex gap-2">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search policies..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-10 w-[200px]"
                  />
                </div>
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="w-[130px]">
                    <SelectValue placeholder="Status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Status</SelectItem>
                    <SelectItem value="draft">Draft</SelectItem>
                    <SelectItem value="active">Active</SelectItem>
                    <SelectItem value="deprecated">Deprecated</SelectItem>
                    <SelectItem value="archived">Archived</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {isLoading ? (
              <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
              </div>
            ) : (
              <TabsContent value="all" className="mt-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Policy</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Rules</TableHead>
                      <TableHead>Version</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead className="w-[50px]"></TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {policies.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                          No policies found
                        </TableCell>
                      </TableRow>
                    ) : (
                      policies.map((policy) => {
                        const TypeIcon = typeIcons[policy.type]
                        const statusInfo = statusConfig[policy.status]

                        return (
                          <TableRow key={policy.id}>
                            <TableCell>
                              <Link
                                to={`/policies/${policy.id}`}
                                className="hover:underline"
                              >
                                <div className="font-medium">{policy.name}</div>
                                <div className="text-sm text-muted-foreground line-clamp-1">
                                  {policy.description}
                                </div>
                              </Link>
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center gap-2">
                                <TypeIcon className="h-4 w-4" />
                                <span className="capitalize">{policy.type}</span>
                              </div>
                            </TableCell>
                            <TableCell>
                              <Badge
                                variant="outline"
                                className={`${statusInfo.color} text-white border-0`}
                              >
                                {statusInfo.label}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <Badge variant="secondary">{policy.definition?.rules?.length || 0} rules</Badge>
                            </TableCell>
                            <TableCell>v{policy.version}</TableCell>
                            <TableCell className="text-muted-foreground">
                              {new Date(policy.created_at).toLocaleDateString()}
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
                                    <Link to={`/policies/${policy.id}`}>View Details</Link>
                                  </DropdownMenuItem>
                                  <DropdownMenuItem>
                                    <Copy className="mr-2 h-4 w-4" />
                                    Duplicate
                                  </DropdownMenuItem>
                                  <DropdownMenuSeparator />
                                  {policy.status === 'draft' && (
                                    <DropdownMenuItem
                                      onClick={() => activateMutation.mutate(policy.id)}
                                      className="text-green-600"
                                    >
                                      <Play className="mr-2 h-4 w-4" />
                                      Activate
                                    </DropdownMenuItem>
                                  )}
                                  {policy.status === 'active' && (
                                    <DropdownMenuItem className="text-yellow-600">
                                      <Pause className="mr-2 h-4 w-4" />
                                      Deprecate
                                    </DropdownMenuItem>
                                  )}
                                  <DropdownMenuItem
                                    onClick={() => {
                                      if (confirm('Are you sure you want to delete this policy?')) {
                                        deleteMutation.mutate(policy.id)
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
              </TabsContent>
            )}
          </Tabs>
        </CardContent>
      </Card>
    </div>
  )
}
