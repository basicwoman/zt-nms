import { useState } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft,
  Server,
  Shield,
  Settings,
  Activity,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Network,
  Cpu,
  Terminal,
  FileCode,
  History,
  Play,
  RefreshCw,
  MoreHorizontal,
  Trash2,
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { devicesApi } from '@/api/client'
import type { Device, DeviceTrustStatus, AttestationReport, ConfigBlock } from '@/types/api'

const trustStatusConfig: Record<string, { icon: React.ElementType; color: string; bgColor: string; label: string }> = {
  trusted: { icon: CheckCircle, color: 'text-green-500', bgColor: 'bg-green-500/10', label: 'Trusted' },
  verified: { icon: CheckCircle, color: 'text-green-500', bgColor: 'bg-green-500/10', label: 'Verified' },
  untrusted: { icon: AlertTriangle, color: 'text-yellow-500', bgColor: 'bg-yellow-500/10', label: 'Untrusted' },
  unknown: { icon: AlertTriangle, color: 'text-yellow-500', bgColor: 'bg-yellow-500/10', label: 'Unknown' },
  compromised: { icon: XCircle, color: 'text-red-500', bgColor: 'bg-red-500/10', label: 'Compromised' },
  quarantined: { icon: Shield, color: 'text-orange-500', bgColor: 'bg-orange-500/10', label: 'Quarantined' },
}

// Mock data
const mockDevice: Device = {
  id: 'dev-001',
  hostname: 'router-core-01',
  vendor: 'Cisco',
  model: 'ASR 9000',
  serial_number: 'FDO12345XYZ',
  os_type: 'IOS-XR',
  os_version: '7.3.2',
  role: 'core_router',
  criticality: 'critical',
  location_id: 'loc-001',
  location_name: 'DC1 - Main Data Center',
  management_ip: '10.0.1.1',
  status: 'online',
  trust_status: 'trusted',
  config_sequence: 42,
  created_at: new Date(Date.now() - 86400000).toISOString(),
  updated_at: new Date(Date.now() - 60000).toISOString(),
}

const mockAttestation: AttestationReport = {
  device_id: 'dev-001',
  timestamp: new Date(Date.now() - 300000).toISOString(),
  measurements: {
    firmware_hash: 'sha256:1234567890abcdef...',
    os_hash: 'sha256:abcdef1234567890...',
    running_config_hash: 'sha256:fedcba0987654321...',
    startup_config_hash: 'sha256:fedcba0987654321...',
    agent_hash: 'sha256:0987654321fedcba...',
    active_processes: ['bgpd', 'ospfd', 'isis', 'sshd', 'snmpd'],
    loaded_modules: ['ip_tables', 'nf_conntrack', 'tun'],
    open_ports: [22, 161, 830, 443],
    network_state: { interfaces: 48, bgp_neighbors: 12 },
  },
  status: 'verified',
  verified_at: new Date(Date.now() - 300000).toISOString(),
  next_attestation: new Date(Date.now() + 3600000).toISOString(),
}

const mockConfigHistory: ConfigBlock[] = [
  {
    id: 'cfg-042',
    device_id: 'dev-001',
    sequence: 42,
    prev_hash: 'sha256:prev041...',
    merkle_root: 'sha256:merkle042...',
    block_hash: 'sha256:block042...',
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    intent: { description: 'Update BGP timers', policy_refs: ['pol-bgp-001'] },
    configuration: { format: 'yang', tree: {} },
    validation: { syntax_check: 'passed', policy_check: 'passed', security_check: 'passed' },
    signatures: {
      author: { identity: 'admin', signature: 'sig...', timestamp: new Date().toISOString() },
      approvers: [],
    },
    deployment: { status: 'verified', applied_at: new Date(Date.now() - 3500000).toISOString() },
  },
  {
    id: 'cfg-041',
    device_id: 'dev-001',
    sequence: 41,
    prev_hash: 'sha256:prev040...',
    merkle_root: 'sha256:merkle041...',
    block_hash: 'sha256:block041...',
    timestamp: new Date(Date.now() - 86400000).toISOString(),
    intent: { description: 'Add new VLAN 100', policy_refs: ['pol-vlan-001'] },
    configuration: { format: 'yang', tree: {} },
    validation: { syntax_check: 'passed', policy_check: 'passed', security_check: 'passed' },
    signatures: {
      author: { identity: 'operator1', signature: 'sig...', timestamp: new Date().toISOString() },
      approvers: [],
    },
    deployment: { status: 'verified', applied_at: new Date(Date.now() - 86300000).toISOString() },
  },
]

export function DeviceDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [isOperationDialogOpen, setIsOperationDialogOpen] = useState(false)
  const [operation, setOperation] = useState({ action: '', parameters: '{}' })

  // Using mock data
  const device = mockDevice
  const attestation = mockAttestation
  const configHistory = mockConfigHistory

  const deleteMutation = useMutation({
    mutationFn: () => devicesApi.delete(id!),
    onSuccess: () => {
      navigate('/devices')
    },
  })

  const executeOperationMutation = useMutation({
    mutationFn: (data: { action: string; parameters: Record<string, unknown> }) =>
      devicesApi.executeOperation(id!, data),
    onSuccess: () => {
      setIsOperationDialogOpen(false)
    },
  })

  const handleExecuteOperation = () => {
    try {
      const params = JSON.parse(operation.parameters)
      executeOperationMutation.mutate({
        action: operation.action,
        parameters: params,
      })
    } catch {
      alert('Invalid JSON parameters')
    }
  }

  const statusInfo = trustStatusConfig[device.trust_status] || trustStatusConfig.unknown
  const StatusIcon = statusInfo.icon

  const isOnline = device.status === 'online'

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" asChild>
            <Link to="/devices">
              <ArrowLeft className="h-4 w-4" />
            </Link>
          </Button>
          <div>
            <div className="flex items-center gap-3">
              <Server className="h-8 w-8" />
              <h1 className="text-3xl font-bold">{device.hostname}</h1>
              <Badge variant={isOnline ? 'default' : 'secondary'}>
                {isOnline ? 'Online' : 'Offline'}
              </Badge>
            </div>
            <p className="text-muted-foreground mt-1">
              {device.vendor} {device.model} - {device.management_ip}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => setIsOperationDialogOpen(true)}>
            <Terminal className="mr-2 h-4 w-4" />
            Execute Operation
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="icon">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem>
                <RefreshCw className="mr-2 h-4 w-4" />
                Trigger Attestation
              </DropdownMenuItem>
              <DropdownMenuItem>
                <Settings className="mr-2 h-4 w-4" />
                Edit Device
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={() => {
                  if (confirm('Are you sure you want to delete this device?')) {
                    deleteMutation.mutate()
                  }
                }}
                className="text-red-600"
              >
                <Trash2 className="mr-2 h-4 w-4" />
                Delete Device
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* Trust Status Banner */}
      <Card className={`border-l-4 ${statusInfo.bgColor}`} style={{ borderLeftColor: statusInfo.color.replace('text-', '') }}>
        <CardContent className="flex items-center gap-4 pt-6">
          <StatusIcon className={`h-8 w-8 ${statusInfo.color}`} />
          <div>
            <h3 className="font-semibold">Trust Status: {statusInfo.label}</h3>
            <p className="text-sm text-muted-foreground">
              Last attestation: {new Date(attestation.verified_at!).toLocaleString()}
              {' | '}
              Next attestation: {new Date(attestation.next_attestation!).toLocaleString()}
            </p>
          </div>
          <Button variant="outline" className="ml-auto">
            View Attestation Details
          </Button>
        </CardContent>
      </Card>

      {/* Device Info Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Role</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xl font-bold capitalize">{device.role.replace(/_/g, ' ')}</div>
            <Badge variant="outline" className="mt-1 capitalize">
              {device.criticality}
            </Badge>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Location</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xl font-bold">{device.location_name}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Config Version</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xl font-bold">v{device.config_sequence}</div>
            <p className="text-xs text-muted-foreground font-mono mt-1">
              {device.current_config_hash ? device.current_config_hash.slice(0, 24) + '...' : 'N/A'}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Status</CardTitle>
          </CardHeader>
          <CardContent>
            <Badge variant={isOnline ? 'default' : 'secondary'} className="uppercase text-xs">
              {device.status}
            </Badge>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="attestation">Attestation</TabsTrigger>
          <TabsTrigger value="config">Configuration</TabsTrigger>
          <TabsTrigger value="operations">Operations</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Device Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Vendor</span>
                  <span className="font-medium">{device.vendor}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Model</span>
                  <span className="font-medium">{device.model}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Serial Number</span>
                  <span className="font-mono">{device.serial_number}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">OS Type</span>
                  <span className="font-medium">{device.os_type}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">OS Version</span>
                  <span className="font-medium">{device.os_version}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Management IP</span>
                  <span className="font-mono">{device.management_ip}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Last Updated</span>
                  <span>{new Date(device.updated_at).toLocaleString()}</span>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Quick Stats</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-green-500/10">
                    <CheckCircle className="h-5 w-5 text-green-500" />
                  </div>
                  <div>
                    <div className="font-medium">Attestation Status</div>
                    <div className="text-sm text-muted-foreground">Verified 5 minutes ago</div>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-blue-500/10">
                    <FileCode className="h-5 w-5 text-blue-500" />
                  </div>
                  <div>
                    <div className="font-medium">Configuration</div>
                    <div className="text-sm text-muted-foreground">42 config changes (chain verified)</div>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-purple-500/10">
                    <Activity className="h-5 w-5 text-purple-500" />
                  </div>
                  <div>
                    <div className="font-medium">Operations</div>
                    <div className="text-sm text-muted-foreground">15 operations today</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="attestation" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Latest Attestation Report</CardTitle>
              <CardDescription>
                Collected at {new Date(attestation.timestamp).toLocaleString()}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-4 md:grid-cols-2">
                <div>
                  <Label className="text-muted-foreground">Firmware Hash</Label>
                  <p className="font-mono text-sm break-all">{attestation.measurements.firmware_hash}</p>
                </div>
                <div>
                  <Label className="text-muted-foreground">OS Hash</Label>
                  <p className="font-mono text-sm break-all">{attestation.measurements.os_hash}</p>
                </div>
                <div>
                  <Label className="text-muted-foreground">Running Config Hash</Label>
                  <p className="font-mono text-sm break-all">{attestation.measurements.running_config_hash}</p>
                </div>
                <div>
                  <Label className="text-muted-foreground">Agent Hash</Label>
                  <p className="font-mono text-sm break-all">{attestation.measurements.agent_hash}</p>
                </div>
              </div>

              <div>
                <Label className="text-muted-foreground">Active Processes</Label>
                <div className="flex flex-wrap gap-1 mt-2">
                  {attestation.measurements.active_processes.map((proc) => (
                    <Badge key={proc} variant="secondary">{proc}</Badge>
                  ))}
                </div>
              </div>

              <div>
                <Label className="text-muted-foreground">Open Ports</Label>
                <div className="flex flex-wrap gap-1 mt-2">
                  {attestation.measurements.open_ports.map((port) => (
                    <Badge key={port} variant="outline">{port}</Badge>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="config" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Configuration History</CardTitle>
              <CardDescription>Immutable chain of configuration changes</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {configHistory.map((config, i) => (
                  <div
                    key={config.id}
                    className="flex items-start gap-4 p-4 rounded-lg border"
                  >
                    <div className="flex flex-col items-center">
                      <div className="p-2 rounded-full bg-primary text-primary-foreground">
                        <FileCode className="h-4 w-4" />
                      </div>
                      {i < configHistory.length - 1 && (
                        <div className="w-px h-full bg-border mt-2" />
                      )}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <div className="font-medium">v{config.sequence}</div>
                        <Badge variant="outline" className="capitalize">
                          {config.deployment?.status}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground mt-1">
                        {config.intent?.description}
                      </p>
                      <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                        <span>By {config.signatures.author.identity}</span>
                        <span>{new Date(config.timestamp).toLocaleString()}</span>
                      </div>
                      <p className="font-mono text-xs text-muted-foreground mt-1">
                        Hash: {config.block_hash.slice(0, 32)}...
                      </p>
                    </div>
                    <Button variant="ghost" size="sm">
                      <History className="h-4 w-4 mr-2" />
                      View Diff
                    </Button>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="operations" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Execute Operation</CardTitle>
              <CardDescription>Run a command or operation on this device</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-3">
                <Button variant="outline" className="h-24 flex-col gap-2">
                  <Play className="h-6 w-6" />
                  <span>Show Running Config</span>
                </Button>
                <Button variant="outline" className="h-24 flex-col gap-2">
                  <Network className="h-6 w-6" />
                  <span>Show Interfaces</span>
                </Button>
                <Button variant="outline" className="h-24 flex-col gap-2">
                  <Activity className="h-6 w-6" />
                  <span>Show BGP Summary</span>
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Operation Dialog */}
      <Dialog open={isOperationDialogOpen} onOpenChange={setIsOperationDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Execute Operation</DialogTitle>
            <DialogDescription>
              Run a command on {device.hostname}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label>Action</Label>
              <Select
                value={operation.action}
                onValueChange={(value) => setOperation({ ...operation, action: value })}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select an action" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="get">Get (Read)</SelectItem>
                  <SelectItem value="get-config">Get Config</SelectItem>
                  <SelectItem value="edit-config">Edit Config</SelectItem>
                  <SelectItem value="exec">Execute Command</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Parameters (JSON)</Label>
              <textarea
                value={operation.parameters}
                onChange={(e) => setOperation({ ...operation, parameters: e.target.value })}
                className="w-full h-32 p-3 rounded-md border bg-background font-mono text-sm"
                placeholder='{"filter": "interfaces"}'
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsOperationDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleExecuteOperation} disabled={executeOperationMutation.isPending}>
              {executeOperationMutation.isPending ? 'Executing...' : 'Execute'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
