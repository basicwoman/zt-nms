import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Server,
  Plus,
  Search,
  Filter,
  MoreHorizontal,
  Wifi,
  WifiOff,
  Shield,
  AlertTriangle,
  Eye,
  Settings,
  Trash2,
  RefreshCw,
  Loader2,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
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
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
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
import { devicesApi } from '@/api/client'
import type { Device, DeviceTrustStatus, DeviceStatus } from '@/types/api'
import { formatRelativeTime } from '@/lib/utils'
import { useTranslation } from '@/i18n/useTranslation'

function TrustStatusBadge({ status }: { status: DeviceTrustStatus }) {
  const variants: Record<string, { variant: 'success' | 'destructive' | 'warning' | 'secondary'; icon: React.ReactNode }> = {
    trusted: { variant: 'success', icon: <Shield className="mr-1 h-3 w-3" /> },
    verified: { variant: 'success', icon: <Shield className="mr-1 h-3 w-3" /> },
    untrusted: { variant: 'warning', icon: <AlertTriangle className="mr-1 h-3 w-3" /> },
    compromised: { variant: 'destructive', icon: <AlertTriangle className="mr-1 h-3 w-3" /> },
    quarantined: { variant: 'warning', icon: <AlertTriangle className="mr-1 h-3 w-3" /> },
    unknown: { variant: 'secondary', icon: null },
  }

  const { variant, icon } = variants[status] || { variant: 'secondary' as const, icon: null }

  return (
    <Badge variant={variant} className="capitalize">
      {icon}
      {status}
    </Badge>
  )
}

function StatusBadge({ status }: { status: DeviceStatus }) {
  const variants: Record<string, { variant: 'success' | 'destructive' | 'warning' | 'secondary'; icon: React.ReactNode }> = {
    online: { variant: 'success', icon: <Wifi className="mr-1 h-3 w-3" /> },
    offline: { variant: 'destructive', icon: <WifiOff className="mr-1 h-3 w-3" /> },
    degraded: { variant: 'warning', icon: <AlertTriangle className="mr-1 h-3 w-3" /> },
    unknown: { variant: 'secondary', icon: null },
  }

  const { variant, icon } = variants[status] || { variant: 'secondary' as const, icon: null }

  return (
    <Badge variant={variant} className="capitalize">
      {icon}
      {status}
    </Badge>
  )
}

interface NewDeviceForm {
  hostname: string
  management_ip: string
  vendor: string
  model: string
  serial_number: string
  os_type: string
  os_version: string
  role: string
  criticality: string
}

const initialFormState: NewDeviceForm = {
  hostname: '',
  management_ip: '',
  vendor: '',
  model: '',
  serial_number: '',
  os_type: '',
  os_version: '',
  role: '',
  criticality: 'medium',
}

export function DevicesPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [roleFilter, setRoleFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null)
  const [isAddDialogOpen, setIsAddDialogOpen] = useState(false)
  const [newDeviceForm, setNewDeviceForm] = useState<NewDeviceForm>(initialFormState)

  // Fetch devices from API
  const { data: devicesData, isLoading, error, refetch } = useQuery({
    queryKey: ['devices', { role: roleFilter !== 'all' ? roleFilter : undefined, status: statusFilter !== 'all' ? statusFilter : undefined }],
    queryFn: () => devicesApi.list({
      role: roleFilter !== 'all' ? roleFilter : undefined,
      status: statusFilter !== 'all' ? statusFilter : undefined,
    }),
  })

  // Register device mutation
  const registerMutation = useMutation({
    mutationFn: (data: NewDeviceForm) => devicesApi.register(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] })
      setIsAddDialogOpen(false)
      setNewDeviceForm(initialFormState)
      alert('Device registered successfully!')
    },
    onError: (error: Error) => {
      alert(`Failed to register device: ${error.message}`)
    },
  })

  // Delete device mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => devicesApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] })
    },
    onError: (error: Error) => {
      alert(`Failed to remove device: ${error.message}`)
    },
  })

  const devices = devicesData?.devices || []

  const filteredDevices = devices.filter((device) => {
    const matchesSearch =
      device.hostname.toLowerCase().includes(search.toLowerCase()) ||
      device.management_ip.includes(search) ||
      device.vendor.toLowerCase().includes(search.toLowerCase())
    const matchesRole = roleFilter === 'all' || device.role === roleFilter
    const matchesStatus = statusFilter === 'all' || device.status === statusFilter
    return matchesSearch && matchesRole && matchesStatus
  })

  const roles = [...new Set(devices.map((d) => d.role))]
  const statuses: DeviceStatus[] = ['online', 'offline', 'degraded', 'unknown']

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">{t('devices.title')}</h1>
          <p className="text-muted-foreground">{t('devices.subtitle')}</p>
        </div>
        <Dialog open={isAddDialogOpen} onOpenChange={setIsAddDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              {t('devices.addDevice')}
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>{t('devices.addNewDevice')}</DialogTitle>
              <DialogDescription>{t('devices.registerDescription')}</DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="hostname">Hostname *</Label>
                  <Input
                    id="hostname"
                    placeholder="router-core-01"
                    value={newDeviceForm.hostname}
                    onChange={(e) => setNewDeviceForm({...newDeviceForm, hostname: e.target.value})}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="management-ip">Management IP *</Label>
                  <Input
                    id="management-ip"
                    placeholder="10.0.0.1"
                    value={newDeviceForm.management_ip}
                    onChange={(e) => setNewDeviceForm({...newDeviceForm, management_ip: e.target.value})}
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="vendor">Vendor *</Label>
                  <Select
                    value={newDeviceForm.vendor}
                    onValueChange={(value) => setNewDeviceForm({...newDeviceForm, vendor: value})}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select vendor" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="Cisco">Cisco</SelectItem>
                      <SelectItem value="Juniper">Juniper</SelectItem>
                      <SelectItem value="Arista">Arista</SelectItem>
                      <SelectItem value="Palo Alto">Palo Alto</SelectItem>
                      <SelectItem value="Fortinet">Fortinet</SelectItem>
                      <SelectItem value="Huawei">Huawei</SelectItem>
                      <SelectItem value="MikroTik">MikroTik</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="model">Model</Label>
                  <Input
                    id="model"
                    placeholder="ASR1001-X"
                    value={newDeviceForm.model}
                    onChange={(e) => setNewDeviceForm({...newDeviceForm, model: e.target.value})}
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="serial_number">Serial Number</Label>
                  <Input
                    id="serial_number"
                    placeholder="FXS12345678"
                    value={newDeviceForm.serial_number}
                    onChange={(e) => setNewDeviceForm({...newDeviceForm, serial_number: e.target.value})}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="os_type">OS Type</Label>
                  <Input
                    id="os_type"
                    placeholder="IOS-XE"
                    value={newDeviceForm.os_type}
                    onChange={(e) => setNewDeviceForm({...newDeviceForm, os_type: e.target.value})}
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="os_version">OS Version</Label>
                  <Input
                    id="os_version"
                    placeholder="17.3.4"
                    value={newDeviceForm.os_version}
                    onChange={(e) => setNewDeviceForm({...newDeviceForm, os_version: e.target.value})}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="role">Role *</Label>
                  <Select
                    value={newDeviceForm.role}
                    onValueChange={(value) => setNewDeviceForm({...newDeviceForm, role: value})}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select role" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="core">Core Router</SelectItem>
                      <SelectItem value="distribution">Distribution</SelectItem>
                      <SelectItem value="access">Access Switch</SelectItem>
                      <SelectItem value="edge">Edge Router</SelectItem>
                      <SelectItem value="firewall">Firewall</SelectItem>
                      <SelectItem value="loadbalancer">Load Balancer</SelectItem>
                      <SelectItem value="wlc">Wireless Controller</SelectItem>
                      <SelectItem value="ap">Access Point</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="criticality">Criticality *</Label>
                  <Select
                    value={newDeviceForm.criticality}
                    onValueChange={(value) => setNewDeviceForm({...newDeviceForm, criticality: value})}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select criticality" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="low">Low</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="critical">Critical</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => {
                setIsAddDialogOpen(false)
                setNewDeviceForm(initialFormState)
              }}>
                Cancel
              </Button>
              <Button
                onClick={() => registerMutation.mutate(newDeviceForm)}
                disabled={registerMutation.isPending || !newDeviceForm.hostname || !newDeviceForm.management_ip || !newDeviceForm.vendor || !newDeviceForm.role}
              >
                {registerMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Add Device
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex flex-wrap gap-4">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search devices..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-10"
              />
            </div>
            <Select value={roleFilter} onValueChange={setRoleFilter}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="Filter by role" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Roles</SelectItem>
                {roles.map((role) => (
                  <SelectItem key={role} value={role}>
                    {role.replace('-', ' ')}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="Filter by status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                {statuses.map((status) => (
                  <SelectItem key={status} value={status} className="capitalize">
                    {status}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button variant="outline" size="icon" onClick={() => refetch()}>
              <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Devices Table */}
      <Card>
        <CardHeader>
          <CardTitle>Managed Devices</CardTitle>
          <CardDescription>
            {isLoading ? 'Loading...' : `${filteredDevices.length} of ${devicesData?.total || devices.length} devices`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <AlertTriangle className="h-8 w-8 text-destructive mb-2" />
              <p className="text-destructive">Failed to load devices</p>
              <p className="text-sm text-muted-foreground">{(error as Error).message}</p>
              <Button variant="outline" onClick={() => refetch()} className="mt-4">
                Retry
              </Button>
            </div>
          ) : filteredDevices.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <Server className="h-8 w-8 text-muted-foreground mb-2" />
              <p className="text-muted-foreground">No devices found</p>
              <p className="text-sm text-muted-foreground">Add a device to get started</p>
            </div>
          ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Hostname</TableHead>
                <TableHead>Vendor / Model</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Management IP</TableHead>
                <TableHead>Trust Status</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Config Version</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredDevices.map((device) => (
                <TableRow key={device.id}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Server className="h-4 w-4 text-muted-foreground" />
                      <span className="font-medium">{device.hostname}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div>
                      <p className="font-medium">{device.vendor}</p>
                      <p className="text-xs text-muted-foreground">{device.model}</p>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="capitalize">
                      {device.role.replace('-', ' ')}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-sm">{device.management_ip}</TableCell>
                  <TableCell>
                    <TrustStatusBadge status={device.trust_status} />
                  </TableCell>
                  <TableCell>
                    <StatusBadge status={device.status} />
                  </TableCell>
                  <TableCell className="font-mono text-sm">v{device.config_sequence}</TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuLabel>Actions</DropdownMenuLabel>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem onClick={() => setSelectedDevice(device)}>
                          <Eye className="mr-2 h-4 w-4" />
                          View Details
                        </DropdownMenuItem>
                        <DropdownMenuItem>
                          <Settings className="mr-2 h-4 w-4" />
                          Configure
                        </DropdownMenuItem>
                        <DropdownMenuItem>
                          <Shield className="mr-2 h-4 w-4" />
                          Request Attestation
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          className="text-destructive"
                          onClick={() => {
                            if (confirm(`Are you sure you want to remove ${device.hostname}?`)) {
                              deleteMutation.mutate(device.id)
                            }
                          }}
                        >
                          <Trash2 className="mr-2 h-4 w-4" />
                          Remove Device
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          )}
        </CardContent>
      </Card>

      {/* Device Details Dialog */}
      <Dialog open={!!selectedDevice} onOpenChange={() => setSelectedDevice(null)}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Server className="h-5 w-5" />
              {selectedDevice?.hostname}
            </DialogTitle>
            <DialogDescription>Device details and configuration</DialogDescription>
          </DialogHeader>
          {selectedDevice && (
            <Tabs defaultValue="details">
              <TabsList>
                <TabsTrigger value="details">Details</TabsTrigger>
                <TabsTrigger value="config">Configuration</TabsTrigger>
                <TabsTrigger value="attestation">Attestation</TabsTrigger>
                <TabsTrigger value="history">History</TabsTrigger>
              </TabsList>
              <TabsContent value="details" className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label className="text-muted-foreground">Hostname</Label>
                    <p className="font-medium">{selectedDevice.hostname}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Management IP</Label>
                    <p className="font-mono">{selectedDevice.management_ip}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Vendor</Label>
                    <p>{selectedDevice.vendor}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Model</Label>
                    <p>{selectedDevice.model}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Serial Number</Label>
                    <p className="font-mono">{selectedDevice.serial_number}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">OS Version</Label>
                    <p>{selectedDevice.os_type} {selectedDevice.os_version}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Role</Label>
                    <p className="capitalize">{selectedDevice.role.replace('-', ' ')}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Criticality</Label>
                    <Badge variant={selectedDevice.criticality === 'critical' ? 'destructive' : 'secondary'}>
                      {selectedDevice.criticality}
                    </Badge>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Location</Label>
                    <p>{selectedDevice.location_name}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Trust Status</Label>
                    <TrustStatusBadge status={selectedDevice.trust_status} />
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Status</Label>
                    <StatusBadge status={selectedDevice.status} />
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Config Version</Label>
                    <p className="font-mono">v{selectedDevice.config_sequence}</p>
                  </div>
                </div>
              </TabsContent>
              <TabsContent value="config">
                <div className="rounded-lg bg-muted p-4">
                  <pre className="text-sm">
                    {`! Configuration for ${selectedDevice.hostname}
! Last updated: ${new Date().toISOString()}
!
hostname ${selectedDevice.hostname}
!
interface GigabitEthernet0/0
  ip address ${selectedDevice.management_ip} 255.255.255.0
  no shutdown
!
`}
                  </pre>
                </div>
              </TabsContent>
              <TabsContent value="attestation">
                <div className="space-y-4">
                  <div className="flex items-center justify-between rounded-lg border p-4">
                    <div>
                      <p className="font-medium">Last Attestation</p>
                      <p className="text-sm text-muted-foreground">
                        {formatRelativeTime(selectedDevice.updated_at)}
                      </p>
                    </div>
                    <TrustStatusBadge status={selectedDevice.trust_status} />
                  </div>
                  <Button>
                    <RefreshCw className="mr-2 h-4 w-4" />
                    Request New Attestation
                  </Button>
                </div>
              </TabsContent>
              <TabsContent value="history">
                <p className="text-muted-foreground">Configuration history will be displayed here...</p>
              </TabsContent>
            </Tabs>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
