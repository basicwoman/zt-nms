import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus,
  Search,
  FileCode,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Server,
  MoreHorizontal,
  Play,
  Undo2,
  Eye,
  GitBranch,
  Upload,
  History,
  Shield,
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
import { configsApi, devicesApi } from '@/api/client'
import type { Deployment, DeploymentStatus } from '@/types/api'

const statusConfig: Record<DeploymentStatus, { icon: React.ElementType; color: string; bgColor: string; label: string }> = {
  pending: { icon: Clock, color: 'text-yellow-500', bgColor: 'bg-yellow-500/10', label: 'Pending' },
  prepared: { icon: FileCode, color: 'text-blue-500', bgColor: 'bg-blue-500/10', label: 'Prepared' },
  committed: { icon: CheckCircle, color: 'text-green-500', bgColor: 'bg-green-500/10', label: 'Committed' },
  verified: { icon: Shield, color: 'text-green-600', bgColor: 'bg-green-600/10', label: 'Verified' },
  failed: { icon: XCircle, color: 'text-red-500', bgColor: 'bg-red-500/10', label: 'Failed' },
  rolled_back: { icon: Undo2, color: 'text-orange-500', bgColor: 'bg-orange-500/10', label: 'Rolled Back' },
}

// Mock deployments data
const mockDeployments: Deployment[] = [
  {
    id: 'dep-001',
    targets: [
      { device_id: 'dev-001', config_block_id: 'cfg-001', status: 'verified' },
      { device_id: 'dev-002', config_block_id: 'cfg-002', status: 'verified' },
    ],
    deployment_strategy: 'rolling',
    overall_status: 'verified',
    created_at: new Date(Date.now() - 3600000).toISOString(),
    created_by: 'admin@company.com',
    approved_by: 'security@company.com',
    completed_at: new Date(Date.now() - 1800000).toISOString(),
  },
  {
    id: 'dep-002',
    targets: [
      { device_id: 'dev-003', config_block_id: 'cfg-003', status: 'pending' },
    ],
    deployment_strategy: 'atomic',
    overall_status: 'pending',
    created_at: new Date(Date.now() - 7200000).toISOString(),
    created_by: 'operator@company.com',
  },
  {
    id: 'dep-003',
    targets: [
      { device_id: 'dev-004', config_block_id: 'cfg-004', status: 'failed', error: 'Connection timeout' },
    ],
    deployment_strategy: 'atomic',
    overall_status: 'failed',
    created_at: new Date(Date.now() - 86400000).toISOString(),
    created_by: 'admin@company.com',
  },
]

export function ConfigsPage() {
  const queryClient = useQueryClient()
  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [isDeployDialogOpen, setIsDeployDialogOpen] = useState(false)
  const [isValidateDialogOpen, setIsValidateDialogOpen] = useState(false)
  const [selectedDeployment, setSelectedDeployment] = useState<Deployment | null>(null)
  const [newDeployment, setNewDeployment] = useState({
    deviceId: '',
    strategy: 'atomic' as 'atomic' | 'rolling' | 'canary',
    config: '{}',
    rollbackOnFailure: true,
  })
  const [validateConfig, setValidateConfig] = useState({
    deviceId: '',
    config: '{}',
    checks: ['syntax', 'policy', 'security'],
  })

  const { data: devicesData } = useQuery({
    queryKey: ['devices-simple'],
    queryFn: () => devicesApi.list({ limit: 100 }),
  })

  const deployMutation = useMutation({
    mutationFn: configsApi.deploy,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['deployments'] })
      setIsDeployDialogOpen(false)
    },
  })

  const validateMutation = useMutation({
    mutationFn: configsApi.validate,
    onSuccess: (result) => {
      alert(result.valid ? 'Configuration is valid!' : `Errors: ${result.errors.join(', ')}`)
    },
  })

  const rollbackMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      configsApi.rollbackDeployment(id, { reason }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['deployments'] })
    },
  })

  const approveMutation = useMutation({
    mutationFn: ({ id, signature }: { id: string; signature: string }) =>
      configsApi.approveDeployment(id, { approver_signature: signature }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['deployments'] })
    },
  })

  const devices = devicesData?.devices || []
  const deployments = mockDeployments // Using mock data for now

  // Calculate stats
  const stats = {
    total: deployments.length,
    pending: deployments.filter((d) => d.overall_status === 'pending').length,
    inProgress: deployments.filter((d) => ['prepared', 'committed'].includes(d.overall_status)).length,
    verified: deployments.filter((d) => d.overall_status === 'verified').length,
    failed: deployments.filter((d) => d.overall_status === 'failed').length,
  }

  const handleDeploy = () => {
    try {
      const config = JSON.parse(newDeployment.config)
      deployMutation.mutate({
        targets: [{ device_id: newDeployment.deviceId, config_block: config }],
        deployment_strategy: newDeployment.strategy,
        verification: {},
        rollback_on_failure: newDeployment.rollbackOnFailure,
      })
    } catch {
      alert('Invalid JSON configuration')
    }
  }

  const handleValidate = () => {
    try {
      const config = JSON.parse(validateConfig.config)
      validateMutation.mutate({
        device_id: validateConfig.deviceId,
        configuration: config,
        checks: validateConfig.checks,
      })
    } catch {
      alert('Invalid JSON configuration')
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Configurations</h1>
          <p className="text-muted-foreground">Manage device configurations and deployments</p>
        </div>
        <div className="flex gap-2">
          <Dialog open={isValidateDialogOpen} onOpenChange={setIsValidateDialogOpen}>
            <DialogTrigger asChild>
              <Button variant="outline">
                <Shield className="mr-2 h-4 w-4" />
                Validate Config
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl">
              <DialogHeader>
                <DialogTitle>Validate Configuration</DialogTitle>
                <DialogDescription>
                  Check a configuration for syntax, policy compliance, and security issues.
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label>Target Device</Label>
                  <Select
                    value={validateConfig.deviceId}
                    onValueChange={(value) => setValidateConfig({ ...validateConfig, deviceId: value })}
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
                  <Label>Checks</Label>
                  <div className="flex gap-2">
                    {['syntax', 'policy', 'security'].map((check) => (
                      <Badge
                        key={check}
                        variant={validateConfig.checks.includes(check) ? 'default' : 'outline'}
                        className="cursor-pointer capitalize"
                        onClick={() => {
                          if (validateConfig.checks.includes(check)) {
                            setValidateConfig({
                              ...validateConfig,
                              checks: validateConfig.checks.filter((c) => c !== check),
                            })
                          } else {
                            setValidateConfig({
                              ...validateConfig,
                              checks: [...validateConfig.checks, check],
                            })
                          }
                        }}
                      >
                        {check}
                      </Badge>
                    ))}
                  </div>
                </div>
                <div className="space-y-2">
                  <Label>Configuration (JSON)</Label>
                  <textarea
                    value={validateConfig.config}
                    onChange={(e) => setValidateConfig({ ...validateConfig, config: e.target.value })}
                    placeholder='{"interfaces": {...}}'
                    className="w-full h-48 p-3 rounded-md border bg-background font-mono text-sm"
                  />
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setIsValidateDialogOpen(false)}>
                  Cancel
                </Button>
                <Button onClick={handleValidate} disabled={validateMutation.isPending}>
                  {validateMutation.isPending ? 'Validating...' : 'Validate'}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <Dialog open={isDeployDialogOpen} onOpenChange={setIsDeployDialogOpen}>
            <DialogTrigger asChild>
              <Button>
                <Upload className="mr-2 h-4 w-4" />
                Deploy Config
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl">
              <DialogHeader>
                <DialogTitle>Deploy Configuration</DialogTitle>
                <DialogDescription>
                  Deploy a new configuration to one or more devices.
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>Target Device</Label>
                    <Select
                      value={newDeployment.deviceId}
                      onValueChange={(value) => setNewDeployment({ ...newDeployment, deviceId: value })}
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
                    <Label>Deployment Strategy</Label>
                    <Select
                      value={newDeployment.strategy}
                      onValueChange={(value) =>
                        setNewDeployment({ ...newDeployment, strategy: value as 'atomic' | 'rolling' | 'canary' })
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="atomic">Atomic (All at once)</SelectItem>
                        <SelectItem value="rolling">Rolling (One by one)</SelectItem>
                        <SelectItem value="canary">Canary (Test first)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="space-y-2">
                  <Label>Configuration (JSON)</Label>
                  <textarea
                    value={newDeployment.config}
                    onChange={(e) => setNewDeployment({ ...newDeployment, config: e.target.value })}
                    placeholder='{"interfaces": {...}}'
                    className="w-full h-48 p-3 rounded-md border bg-background font-mono text-sm"
                  />
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    id="rollback"
                    checked={newDeployment.rollbackOnFailure}
                    onChange={(e) => setNewDeployment({ ...newDeployment, rollbackOnFailure: e.target.checked })}
                    className="rounded border-gray-300"
                  />
                  <Label htmlFor="rollback">Automatically rollback on failure</Label>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setIsDeployDialogOpen(false)}>
                  Cancel
                </Button>
                <Button onClick={handleDeploy} disabled={deployMutation.isPending}>
                  {deployMutation.isPending ? 'Deploying...' : 'Deploy'}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <FileCode className="h-4 w-4" /> Total
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Clock className="h-4 w-4 text-yellow-500" /> Pending
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-yellow-600">{stats.pending}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Play className="h-4 w-4 text-blue-500" /> In Progress
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-600">{stats.inProgress}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-green-500" /> Verified
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{stats.verified}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <XCircle className="h-4 w-4 text-red-500" /> Failed
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{stats.failed}</div>
          </CardContent>
        </Card>
      </div>

      {/* Deployments Table */}
      <Card>
        <CardHeader>
          <CardTitle>Deployments</CardTitle>
          <CardDescription>View and manage configuration deployments</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between mb-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search deployments..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10 w-[250px]"
              />
            </div>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[150px]">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="pending">Pending</SelectItem>
                <SelectItem value="prepared">Prepared</SelectItem>
                <SelectItem value="committed">Committed</SelectItem>
                <SelectItem value="verified">Verified</SelectItem>
                <SelectItem value="failed">Failed</SelectItem>
                <SelectItem value="rolled_back">Rolled Back</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Deployment ID</TableHead>
                <TableHead>Targets</TableHead>
                <TableHead>Strategy</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Created By</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {deployments.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                    No deployments found
                  </TableCell>
                </TableRow>
              ) : (
                deployments.map((deployment) => {
                  const statusInfo = statusConfig[deployment.overall_status]
                  const StatusIcon = statusInfo.icon

                  return (
                    <TableRow key={deployment.id}>
                      <TableCell>
                        <div className="font-mono text-sm">{deployment.id}</div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          <Server className="h-4 w-4" />
                          <span>{deployment.targets.length} device(s)</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="capitalize">
                          {deployment.deployment_strategy}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <StatusIcon className={`h-4 w-4 ${statusInfo.color}`} />
                          <span>{statusInfo.label}</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {deployment.created_by}
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {new Date(deployment.created_at).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => setSelectedDeployment(deployment)}>
                              <Eye className="mr-2 h-4 w-4" />
                              View Details
                            </DropdownMenuItem>
                            <DropdownMenuItem>
                              <History className="mr-2 h-4 w-4" />
                              View History
                            </DropdownMenuItem>
                            {deployment.overall_status === 'pending' && (
                              <>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem
                                  onClick={() => approveMutation.mutate({ id: deployment.id, signature: 'mock' })}
                                  className="text-green-600"
                                >
                                  <CheckCircle className="mr-2 h-4 w-4" />
                                  Approve
                                </DropdownMenuItem>
                              </>
                            )}
                            {['verified', 'committed'].includes(deployment.overall_status) && (
                              <>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem
                                  onClick={() => rollbackMutation.mutate({ id: deployment.id, reason: 'Manual rollback' })}
                                  className="text-orange-600"
                                >
                                  <Undo2 className="mr-2 h-4 w-4" />
                                  Rollback
                                </DropdownMenuItem>
                              </>
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
        </CardContent>
      </Card>

      {/* Deployment Detail Dialog */}
      {selectedDeployment && (
        <Dialog open={!!selectedDeployment} onOpenChange={() => setSelectedDeployment(null)}>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Deployment Details</DialogTitle>
            </DialogHeader>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-muted-foreground">Deployment ID</Label>
                  <p className="font-mono">{selectedDeployment.id}</p>
                </div>
                <div>
                  <Label className="text-muted-foreground">Strategy</Label>
                  <Badge variant="outline" className="capitalize">
                    {selectedDeployment.deployment_strategy}
                  </Badge>
                </div>
                <div>
                  <Label className="text-muted-foreground">Created By</Label>
                  <p>{selectedDeployment.created_by}</p>
                </div>
                <div>
                  <Label className="text-muted-foreground">Approved By</Label>
                  <p>{selectedDeployment.approved_by || 'Pending approval'}</p>
                </div>
              </div>
              <div>
                <Label className="text-muted-foreground">Targets</Label>
                <div className="mt-2 space-y-2">
                  {selectedDeployment.targets.map((target, i) => {
                    const targetStatus = statusConfig[target.status]
                    const TargetIcon = targetStatus.icon
                    return (
                      <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-muted">
                        <div className="flex items-center gap-3">
                          <Server className="h-4 w-4" />
                          <span className="font-mono text-sm">{target.device_id}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <TargetIcon className={`h-4 w-4 ${targetStatus.color}`} />
                          <span>{targetStatus.label}</span>
                        </div>
                        {target.error && (
                          <span className="text-red-500 text-sm">{target.error}</span>
                        )}
                      </div>
                    )
                  })}
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-muted-foreground">Created</Label>
                  <p>{new Date(selectedDeployment.created_at).toLocaleString()}</p>
                </div>
                <div>
                  <Label className="text-muted-foreground">Completed</Label>
                  <p>
                    {selectedDeployment.completed_at
                      ? new Date(selectedDeployment.completed_at).toLocaleString()
                      : 'In progress'}
                  </p>
                </div>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      )}
    </div>
  )
}
